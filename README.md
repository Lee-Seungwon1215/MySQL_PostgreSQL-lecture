# PQC Signature Storage Lab for MySQL and PostgreSQL

This repository contains hands-on examples for measuring how post-quantum
signature sizes affect database storage layouts in MySQL and PostgreSQL.

The examples compare:

- RSA-2048
- ML-DSA-65, a post-quantum digital signature scheme provided by `pqcrypto`

The lab covers three storage designs:

1. Single table: documents and signatures are stored in the same table.
2. Split table: documents and signatures are stored in separate tables.
3. Split table + Merkle Tree: documents are batched, and only the Merkle root is signed.

The code is intended for Ubuntu or WSL2 Ubuntu.

---

## 1. Install System Packages

```bash
sudo apt update
sudo apt upgrade -y

sudo apt install -y python3 python3-pip python3-venv \
    mysql-server postgresql postgresql-contrib
```

Start database services:

```bash
sudo service mysql start
sudo service postgresql start
```

On non-WSL Linux systems, `systemctl` may also be available:

```bash
sudo systemctl start mysql
sudo systemctl start postgresql
```

---

## 2. Create the MySQL Lab Database

Open the MySQL root shell:

```bash
sudo mysql
```

Run:

```sql
CREATE DATABASE pqc_mysql_lab;
CREATE USER 'pqc_user'@'localhost' IDENTIFIED BY 'pqc_pass';
GRANT ALL PRIVILEGES ON pqc_mysql_lab.* TO 'pqc_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Check the connection:

```bash
mysql -u pqc_user -p pqc_mysql_lab
```

Password:

```text
pqc_pass
```

Exit:

```sql
EXIT;
```

---

## 3. Create the PostgreSQL Lab Database

Open the PostgreSQL admin shell:

```bash
sudo -u postgres psql
```

Run:

```sql
CREATE USER pqc_user WITH PASSWORD 'pqc_pass';
CREATE DATABASE pqc_postgres_lab OWNER pqc_user;
\q
```

Check the connection:

```bash
psql -h localhost -U pqc_user -d pqc_postgres_lab
```

Password:

```text
pqc_pass
```

Exit:

```sql
\q
```

---

## 4. Set Up Python

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

Verify the Python dependencies:

```bash
python -c "import cryptography, pqcrypto, pymysql, psycopg2; print('OK')"
```

---

## 5. Run the MySQL Measurements

Run the examples in the following order:

```bash
python MySQL/example1_single_table.py | tee MySQL/mysql_results.md
python MySQL/example2_split_table.py | tee -a MySQL/mysql_results.md
python MySQL/example3_split_merkle.py | tee -a MySQL/mysql_results.md
BATCH_SIZE=512 python MySQL/example3_split_merkle.py | tee -a MySQL/mysql_results.md
```

---

## 6. Run the PostgreSQL Measurements

Run the examples in the following order:

```bash
python PostgreSQL/example1_single_table.py | tee PostgreSQL/postgre_results.md
python PostgreSQL/example2_split_table.py | tee -a PostgreSQL/postgre_results.md
python PostgreSQL/example3_split_merkle.py | tee -a PostgreSQL/postgre_results.md
BATCH_SIZE=512 python PostgreSQL/example3_split_merkle.py | tee -a PostgreSQL/postgre_results.md
```

---

## 7. Change Experiment Size

The default document count is `10000`.

To run 50000 documents:

```bash
DOC_COUNT=50000 python MySQL/example1_single_table.py
DOC_COUNT=50000 python MySQL/example2_split_table.py
DOC_COUNT=50000 python MySQL/example3_split_merkle.py
DOC_COUNT=50000 BATCH_SIZE=512 python MySQL/example3_split_merkle.py
```

PostgreSQL:

```bash
DOC_COUNT=50000 python PostgreSQL/example1_single_table.py
DOC_COUNT=50000 python PostgreSQL/example2_split_table.py
DOC_COUNT=50000 python PostgreSQL/example3_split_merkle.py
DOC_COUNT=50000 BATCH_SIZE=512 python PostgreSQL/example3_split_merkle.py
```

---

## 8. Output Metrics

Each example prints the following metrics:

| Metric | Meaning |
|---|---|
| `signature` or `batch_signature` | Digital signature size in bytes |
| `proof_path` | Merkle proof size in bytes |
| `insert_time` | Insert benchmark time |
| `table_size` | Table data size |
| `index_size` | Index size |
| `toast_size` | PostgreSQL TOAST size |
| `total_size` | Total storage size |

Notes:

- PostgreSQL large `BYTEA` values can be moved to TOAST storage, so `total_size` is more important than `table_size`.

---

## 9. Relation to the Paper

The included theory and lab materials are based on the idea from
`B_tree_on_MySQL_LNCS.pdf`: large PQC signatures can affect relational database
storage structures, especially MySQL InnoDB B+-Tree layouts.

This repository is a teaching-oriented version of that idea. It uses RSA-2048
and ML-DSA-65 with 10000 documents by default, rather than reproducing the full
paper benchmark with RSA-7680, Dilithium3, AIMer-192f/s, and 1000000 rows.

The important teaching point is:

```text
Single table: simple, but large PQC signatures increase storage cost.
Split table: document table becomes lighter, but signature count is unchanged.
Split + Merkle Tree: signatures are stored per batch, reducing PQC storage cost.
```

---

## 10. Files

MySQL examples:

```text
MySQL/example1_single_table.py
MySQL/example2_split_table.py
MySQL/example3_split_merkle.py
```

PostgreSQL examples:

```text
PostgreSQL/example1_single_table.py
PostgreSQL/example2_split_table.py
PostgreSQL/example3_split_merkle.py
```

Result files are generated when running the examples with `tee`:

```text
MySQL/mysql_results.md
PostgreSQL/postgre_results.md
```
