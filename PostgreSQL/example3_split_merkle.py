import hashlib
import os
import time

import psycopg2
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from pqcrypto.sign import ml_dsa_65


DB_CONFIG = {
    "host": "localhost",
    "user": "pqc_user",
    "password": "pqc_pass",
    "dbname": "pqc_postgres_lab",
}

DOC_COUNT = int(os.getenv("DOC_COUNT", "10000"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "32"))
TABLES = {
    "RSA-2048": (
        "lab_merkle_rsa_2048_documents",
        "lab_merkle_rsa_2048_signature_batches",
    ),
    "ML-DSA-65": (
        "lab_merkle_mldsa_65_documents",
        "lab_merkle_mldsa_65_signature_batches",
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


def sha256(data):
    return hashlib.sha256(data).digest()


def document_hash(title, author, amount, body):
    payload = f"{title}|{author}|{amount}|{body}".encode("utf-8")
    return sha256(payload)


def build_merkle_tree(leaves):
    levels = [leaves]
    current = leaves
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            next_level.append(sha256(left + right))
        levels.append(next_level)
        current = next_level
    return levels


def proof_path(levels, index):
    proof = []
    current_index = index
    for level in levels[:-1]:
        sibling_index = current_index ^ 1
        if sibling_index >= len(level):
            sibling_index = current_index
        proof.append(level[sibling_index])
        current_index //= 2
    return b"".join(proof)


def verify_proof(leaf, proof, root, index):
    current = leaf
    current_index = index
    for i in range(0, len(proof), 32):
        sibling = proof[i : i + 32]
        if current_index % 2 == 0:
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)
        current_index //= 2
    return current == root


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


def setup_database(conn, doc_table, batch_table):
    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {doc_table}")
        cur.execute(f"DROP TABLE IF EXISTS {batch_table}")
        cur.execute(
            f"""
            CREATE TABLE {batch_table} (
                id BIGSERIAL PRIMARY KEY,
                signature_algorithm VARCHAR(32) NOT NULL,
                merkle_root BYTEA NOT NULL,
                public_key BYTEA NOT NULL,
                signature BYTEA NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(f"CREATE INDEX idx_{batch_table}_algorithm ON {batch_table}(signature_algorithm)")
        cur.execute(
            f"""
            CREATE TABLE {doc_table} (
                id BIGSERIAL PRIMARY KEY,
                title VARCHAR(128) NOT NULL,
                author VARCHAR(64) NOT NULL,
                amount_krw BIGINT NOT NULL,
                document_body TEXT NOT NULL,
                document_hash BYTEA NOT NULL,
                batch_id BIGINT NOT NULL REFERENCES {batch_table}(id),
                leaf_index INTEGER NOT NULL,
                proof_path BYTEA NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(f"CREATE INDEX idx_{doc_table}_batch ON {doc_table}(batch_id)")
        cur.execute(f"CREATE INDEX idx_{doc_table}_doc_hash ON {doc_table}(document_hash)")
    conn.commit()


def table_stats(conn, table_name):
    with conn.cursor() as cur:
        cur.execute(f"ANALYZE {table_name}")
        cur.execute(f"SELECT COUNT(*) FROM {table_name}")
        row_count = cur.fetchone()[0]
        cur.execute(
            """
            SELECT
                pg_relation_size(%s),
                pg_indexes_size(%s),
                pg_total_relation_size(%s)
            """,
            (table_name, table_name, table_name),
        )
        table_bytes, index_bytes, total_bytes = cur.fetchone()
        cur.execute(
            """
            SELECT
                CASE
                    WHEN c.reltoastrelid = 0 THEN 0
                    ELSE pg_total_relation_size(c.reltoastrelid)
                END
            FROM pg_class c
            WHERE c.oid = %s::regclass
            """,
            (table_name,),
        )
        toast_bytes = cur.fetchone()[0]
    return row_count, table_bytes, index_bytes, total_bytes, toast_bytes


def mb(value):
    return value / 1024 / 1024


def run_algorithm(conn, doc_table, batch_table, algorithm, signer, public_key_bytes):
    batch_sql = (
        f"INSERT INTO {batch_table} "
        "(signature_algorithm, merkle_root, public_key, signature) "
        "VALUES (%s, %s, %s, %s) RETURNING id"
    )
    doc_sql = (
        f"INSERT INTO {doc_table} "
        "(title, author, amount_krw, document_body, document_hash, "
        "batch_id, leaf_index, proof_path) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    )

    start = time.perf_counter()
    first_signature = None
    first_leaf = None
    first_proof = None
    first_root = None

    with conn.cursor() as cur:
        for start_index in range(0, DOC_COUNT, BATCH_SIZE):
            docs = []
            leaves = []
            for offset in range(min(BATCH_SIZE, DOC_COUNT - start_index)):
                i = start_index + offset
                title, author, amount, body = make_document(i)
                digest = document_hash(title, author, amount, body)
                docs.append((title, author, amount, body, digest))
                leaves.append(digest)

            levels = build_merkle_tree(leaves)
            root = levels[-1][0]
            signature = signer(root)
            cur.execute(
                batch_sql,
                (
                    algorithm,
                    psycopg2.Binary(root),
                    psycopg2.Binary(public_key_bytes),
                    psycopg2.Binary(signature),
                ),
            )
            batch_id = cur.fetchone()[0]

            rows = []
            for leaf_index, doc in enumerate(docs):
                proof = proof_path(levels, leaf_index)
                rows.append(
                    (
                        doc[0],
                        doc[1],
                        doc[2],
                        doc[3],
                        psycopg2.Binary(doc[4]),
                        batch_id,
                        leaf_index,
                        psycopg2.Binary(proof),
                    )
                )
                if first_leaf is None:
                    first_leaf = doc[4]
                    first_proof = proof
                    first_root = root
                    first_signature = signature
            cur.executemany(doc_sql, rows)
        conn.commit()

    elapsed = time.perf_counter() - start
    assert verify_proof(first_leaf, first_proof, first_root, 0)
    return elapsed, len(first_signature), len(first_proof)


def main():
    rsa_private, _, rsa_public_bytes = generate_rsa_keypair()
    mldsa_public, mldsa_secret = ml_dsa_65.generate_keypair()

    conn = psycopg2.connect(**DB_CONFIG)
    try:
        results = []
        doc_table, batch_table = TABLES["RSA-2048"]
        setup_database(conn, doc_table, batch_table)
        elapsed, sig_size, proof_size = run_algorithm(
            conn,
            doc_table,
            batch_table,
            "RSA-2048",
            lambda root: sign_rsa(rsa_private, root),
            rsa_public_bytes,
        )
        doc_stats = table_stats(conn, doc_table)
        batch_stats = table_stats(conn, batch_table)
        results.append(
            (
                "RSA-2048",
                sig_size,
                proof_size,
                elapsed,
                doc_table,
                batch_table,
                doc_stats,
                batch_stats,
            )
        )

        doc_table, batch_table = TABLES["ML-DSA-65"]
        setup_database(conn, doc_table, batch_table)
        elapsed, sig_size, proof_size = run_algorithm(
            conn,
            doc_table,
            batch_table,
            "ML-DSA-65",
            lambda root: ml_dsa_65.sign(mldsa_secret, root),
            mldsa_public,
        )
        doc_stats = table_stats(conn, doc_table)
        batch_stats = table_stats(conn, batch_table)
        results.append(
            (
                "ML-DSA-65",
                sig_size,
                proof_size,
                elapsed,
                doc_table,
                batch_table,
                doc_stats,
                batch_stats,
            )
        )

        print("\n[PostgreSQL split table + Merkle tree]")
        print(f"batch_size={BATCH_SIZE}")
        for (
            algorithm,
            sig_size,
            proof_size,
            elapsed,
            doc_table,
            batch_table,
            doc_stats,
            batch_stats,
        ) in results:
            total_bytes = doc_stats[3] + batch_stats[3]
            print(
                f"{algorithm}: batch_signature={sig_size} bytes, "
                f"proof_path={proof_size} bytes, "
                f"insert_time={elapsed:.3f}s"
            )
            print(
                f"{doc_table}: rows={doc_stats[0]}, "
                f"table={mb(doc_stats[1]):.2f} MB, index={mb(doc_stats[2]):.2f} MB, "
                f"toast={mb(doc_stats[4]):.2f} MB"
            )
            print(
                f"{batch_table}: rows={batch_stats[0]}, "
                f"table={mb(batch_stats[1]):.2f} MB, index={mb(batch_stats[2]):.2f} MB, "
                f"toast={mb(batch_stats[4]):.2f} MB"
            )
            print(
                f"total_size={mb(total_bytes):.2f} MB, "
                f"toast_size={mb(doc_stats[4] + batch_stats[4]):.2f} MB"
            )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
