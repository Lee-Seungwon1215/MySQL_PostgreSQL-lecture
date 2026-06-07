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
    "RSA-2048": "lab_single_rsa_2048_documents",
    "ML-DSA-65": "lab_single_mldsa_65_documents",
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


def verify_rsa(public_key, digest, signature):
    public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())
    return True


def setup_database(conn, table_name):
    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {table_name}")
        cur.execute(
            f"""
            CREATE TABLE {table_name} (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(128) NOT NULL,
                author VARCHAR(64) NOT NULL,
                amount_krw BIGINT NOT NULL,
                document_body TEXT NOT NULL,
                document_hash BINARY(32) NOT NULL,
                signature_algorithm VARCHAR(32) NOT NULL,
                public_key BLOB NOT NULL,
                signature BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_algorithm (signature_algorithm),
                INDEX idx_doc_hash (document_hash)
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


def run_algorithm(conn, table_name, algorithm, signer, public_key_bytes):
    sql = (
        f"INSERT INTO {table_name} "
        "(title, author, amount_krw, document_body, document_hash, "
        "signature_algorithm, public_key, signature) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    )
    start = time.perf_counter()
    first_digest = None
    first_signature = None

    with conn.cursor() as cur:
        for i in range(DOC_COUNT):
            title, author, amount, body = make_document(i)
            digest = document_hash(title, author, amount, body)
            signature = signer(digest)
            if i == 0:
                first_digest = digest
                first_signature = signature
            cur.execute(
                sql,
                (
                    title,
                    author,
                    amount,
                    body,
                    digest,
                    algorithm,
                    public_key_bytes,
                    signature,
                ),
            )
        conn.commit()

    elapsed = time.perf_counter() - start
    return elapsed, len(first_signature), first_digest, first_signature


def main():
    rsa_private, rsa_public, rsa_public_bytes = generate_rsa_keypair()
    mldsa_public, mldsa_secret = ml_dsa_65.generate_keypair()

    conn = pymysql.connect(**DB_CONFIG)
    try:
        results = []
        setup_database(conn, TABLES["RSA-2048"])
        rsa_elapsed, rsa_sig_size, rsa_digest, rsa_sig = run_algorithm(
            conn,
            TABLES["RSA-2048"],
            "RSA-2048",
            lambda digest: sign_rsa(rsa_private, digest),
            rsa_public_bytes,
        )
        verify_rsa(rsa_public, rsa_digest, rsa_sig)
        row_count, data_bytes, index_bytes, total_bytes = table_stats(
            conn, TABLES["RSA-2048"]
        )
        results.append(
            (
                "RSA-2048",
                TABLES["RSA-2048"],
                rsa_sig_size,
                rsa_elapsed,
                row_count,
                data_bytes,
                index_bytes,
                total_bytes,
            )
        )

        setup_database(conn, TABLES["ML-DSA-65"])
        mldsa_elapsed, mldsa_sig_size, mldsa_digest, mldsa_sig = run_algorithm(
            conn,
            TABLES["ML-DSA-65"],
            "ML-DSA-65",
            lambda digest: ml_dsa_65.sign(mldsa_secret, digest),
            mldsa_public,
        )
        assert ml_dsa_65.verify(mldsa_public, mldsa_digest, mldsa_sig)
        row_count, data_bytes, index_bytes, total_bytes = table_stats(
            conn, TABLES["ML-DSA-65"]
        )
        results.append(
            (
                "ML-DSA-65",
                TABLES["ML-DSA-65"],
                mldsa_sig_size,
                mldsa_elapsed,
                row_count,
                data_bytes,
                index_bytes,
                total_bytes,
            )
        )

        print("\n[MySQL single table]")
        for (
            algorithm,
            table_name,
            sig_size,
            elapsed,
            row_count,
            data_bytes,
            index_bytes,
            total_bytes,
        ) in results:
            print(f"table: {table_name}")
            print(f"rows: {row_count}")
            print(
                f"{algorithm}: signature={sig_size} bytes, "
                f"insert_time={elapsed:.3f}s"
            )
            print(
                f"table_size={mb(data_bytes):.2f} MB, "
                f"index_size={mb(index_bytes):.2f} MB, "
                f"total_size={mb(total_bytes):.2f} MB"
            )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
