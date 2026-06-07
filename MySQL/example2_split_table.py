import hashlib
import os
import time

import pymysql
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from pqcrypto.sign import ml_dsa_65


DB_CONFIG = {
    "host": "localhost",
    "user": "pqc_user",
    "password": "pqc_pass",
    "database": "pqc_mysql_lab",
    "charset": "utf8mb4",
    "autocommit": False,
}

DOC_COUNT = int(os.getenv("DOC_COUNT", "10000"))
TABLES = {
    "RSA-2048": (
        "lab_split_rsa_2048_documents",
        "lab_split_rsa_2048_document_signatures",
        "fk_split_rsa_2048_document",
    ),
    "ML-DSA-65": (
        "lab_split_mldsa_65_documents",
        "lab_split_mldsa_65_document_signatures",
        "fk_split_mldsa_65_document",
    ),
}


def make_document(i):
    title = f"Contract-{i:06d}"
    author = f"employee-{i % 17:02d}"
    amount = 1_000_000 + (i * 37_911) % 90_000_000
    body = (
        f"Contract number {i:06d}\n"
        f"Author: {author}\n"
        f"Amount KRW: {amount}\n"
        "This document is stored for a database integrity migration lab.\n"
    )
    return title, author, amount, body


def document_hash(title, author, amount, body):
    payload = f"{title}|{author}|{amount}|{body}".encode("utf-8")
    return hashlib.sha256(payload).digest()


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_bytes


def sign_rsa(private_key, digest):
    return private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())


def setup_database(conn, doc_table, sig_table, constraint_name):
    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {sig_table}")
        cur.execute(f"DROP TABLE IF EXISTS {doc_table}")
        cur.execute(
            f"""
            CREATE TABLE {doc_table} (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(128) NOT NULL,
                author VARCHAR(64) NOT NULL,
                amount_krw BIGINT NOT NULL,
                document_body TEXT NOT NULL,
                document_hash BINARY(32) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_doc_hash (document_hash)
            ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
            """
        )
        cur.execute(
            f"""
            CREATE TABLE {sig_table} (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                document_id BIGINT NOT NULL,
                signature_algorithm VARCHAR(32) NOT NULL,
                public_key BLOB NOT NULL,
                signature BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_document_id (document_id),
                INDEX idx_algorithm (signature_algorithm),
                CONSTRAINT {constraint_name}
                    FOREIGN KEY (document_id) REFERENCES {doc_table}(id)
            ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
            """
        )
    conn.commit()


def table_stats(conn, table_name):
    with conn.cursor() as cur:
        cur.execute(f"ANALYZE TABLE {table_name}")
        cur.fetchall()
        cur.execute(f"SELECT COUNT(*) FROM {table_name}")
        row_count = cur.fetchone()[0]
        cur.execute(
            """
            SELECT data_length, index_length, data_length + index_length
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = %s
            """,
            (table_name,),
        )
        data_bytes, index_bytes, total_bytes = cur.fetchone()
    return row_count, data_bytes, index_bytes, total_bytes


def mb(value):
    return value / 1024 / 1024


def run_algorithm(conn, doc_table, sig_table, algorithm, signer, public_key_bytes):
    doc_sql = (
        f"INSERT INTO {doc_table} "
        "(title, author, amount_krw, document_body, document_hash) "
        "VALUES (%s, %s, %s, %s, %s)"
    )
    sig_sql = (
        f"INSERT INTO {sig_table} "
        "(document_id, signature_algorithm, public_key, signature) "
        "VALUES (%s, %s, %s, %s)"
    )

    start = time.perf_counter()
    first_signature = None
    with conn.cursor() as cur:
        for i in range(DOC_COUNT):
            title, author, amount, body = make_document(i)
            digest = document_hash(title, author, amount, body)
            signature = signer(digest)
            if i == 0:
                first_signature = signature
            cur.execute(doc_sql, (title, author, amount, body, digest))
            document_id = cur.lastrowid
            cur.execute(sig_sql, (document_id, algorithm, public_key_bytes, signature))
        conn.commit()

    elapsed = time.perf_counter() - start
    return elapsed, len(first_signature)


def main():
    rsa_private, _, rsa_public_bytes = generate_rsa_keypair()
    mldsa_public, mldsa_secret = ml_dsa_65.generate_keypair()

    conn = pymysql.connect(**DB_CONFIG)
    try:
        results = []
        doc_table, sig_table, constraint_name = TABLES["RSA-2048"]
        setup_database(conn, doc_table, sig_table, constraint_name)
        elapsed, sig_size = run_algorithm(
            conn,
            doc_table,
            sig_table,
            "RSA-2048",
            lambda digest: sign_rsa(rsa_private, digest),
            rsa_public_bytes,
        )
        doc_stats = table_stats(conn, doc_table)
        sig_stats = table_stats(conn, sig_table)
        results.append(("RSA-2048", sig_size, elapsed, doc_table, sig_table, doc_stats, sig_stats))

        doc_table, sig_table, constraint_name = TABLES["ML-DSA-65"]
        setup_database(conn, doc_table, sig_table, constraint_name)
        elapsed, sig_size = run_algorithm(
            conn,
            doc_table,
            sig_table,
            "ML-DSA-65",
            lambda digest: ml_dsa_65.sign(mldsa_secret, digest),
            mldsa_public,
        )
        doc_stats = table_stats(conn, doc_table)
        sig_stats = table_stats(conn, sig_table)
        results.append(("ML-DSA-65", sig_size, elapsed, doc_table, sig_table, doc_stats, sig_stats))

        print("\n[MySQL split table]")
        for algorithm, sig_size, elapsed, doc_table, sig_table, doc_stats, sig_stats in results:
            total_bytes = doc_stats[3] + sig_stats[3]
            print(
                f"{algorithm}: signature={sig_size} bytes, "
                f"insert_time={elapsed:.3f}s"
            )
            print(
                f"{doc_table}: rows={doc_stats[0]}, "
                f"table={mb(doc_stats[1]):.2f} MB, index={mb(doc_stats[2]):.2f} MB"
            )
            print(
                f"{sig_table}: rows={sig_stats[0]}, "
                f"table={mb(sig_stats[1]):.2f} MB, index={mb(sig_stats[2]):.2f} MB"
            )
            print(f"total_size={mb(total_bytes):.2f} MB")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
