"""
Seeds the Neo4j graph with bait data for the CloudAIWallet honeypot.
All values are obviously fake placeholders marked as honeypot bait.

Usage:
    NEO4J_URI=bolt://localhost:7687 NEO4J_PASS=neo4j python scripts/seed_neo4j.py
"""
import os
from neo4j import GraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "neo4j")

CYPHER_SETUP = [
    "MATCH (n) DETACH DELETE n",

    # Users
    "CREATE (u:User {id:1, username:'admin', email:'admin@example-honeypot.local', "
    "role:'admin', tier:'enterprise', wallet_address:'0xBAITADDRESS000000000000000000000000000001'})",
    "CREATE (u:User {id:2, username:'trading_bot', email:'bot@example-honeypot.local', "
    "role:'service', tier:'enterprise', wallet_address:'0xBAITADDRESS000000000000000000000000000002'})",
    "CREATE (u:User {id:3, username:'trader_one', email:'trader@example-honeypot.local', "
    "role:'user', tier:'pro', wallet_address:'0xBAITADDRESS000000000000000000000000000003'})",
    "CREATE (u:User {id:4, username:'developer', email:'dev@example-honeypot.local', "
    "role:'developer', tier:'pro', wallet_address:'0xBAITADDRESS000000000000000000000000000004'})",
    "CREATE (u:User {id:5, username:'test_user', email:'test@example-honeypot.local', "
    "role:'user', tier:'free'})",

    # Admin (with bait credentials)
    "CREATE (a:Admin {id:1, username:'admin', email:'admin@example-honeypot.local', "
    "password_hash:'HONEYPOT_BAIT_HASH_ADMIN', "
    "aws_access_key:'HONEYPOT_BAIT_AWS_ACCESS_KEY', "
    "aws_secret_key:'HONEYPOT_BAIT_AWS_SECRET_KEY'})",

    # Wallets
    "CREATE (w:Wallet {id:1, address:'0xBAITADDRESS000000000000000000000000000001', "
    "balance_eth:1247.32, balance_btc:34.5, owner_id:1})",
    "CREATE (w:Wallet {id:2, address:'0xBAITADDRESS000000000000000000000000000003', "
    "balance_eth:847.21, balance_btc:0, owner_id:3})",
    "CREATE (w:Wallet {id:3, address:'0xBAITADDRESS000000000000000000000000000002', "
    "balance_eth:0, balance_btc:62.7, owner_id:2})",

    # Seed phrases (bait)
    "CREATE (s:SeedPhrase {id:1, owner_id:1, "
    "mnemonic:'HONEYPOT BAIT SEED PHRASE TWELVE WORDS PLACEHOLDER VALUE FOR DEMO ONLY DO NOT USE', "
    "derivation_path:\"m/44'/60'/0'/0/0\"})",
    "CREATE (s:SeedPhrase {id:2, owner_id:2, "
    "mnemonic:'HONEYPOT BAIT SECONDARY MNEMONIC ANOTHER PLACEHOLDER VALUE EXAMPLE ONLY NOT REAL', "
    "derivation_path:\"m/44'/0'/0'/0/0\"})",

    # API keys (bait)
    "CREATE (k:APIKey {id:1, owner_id:1, key:'HONEYPOT_BAIT_API_KEY_INTERNAL', "
    "permissions:'admin', name:'Internal Service Key'})",
    "CREATE (k:APIKey {id:2, owner_id:1, key:'HONEYPOT_BAIT_API_KEY_STRIPE', "
    "permissions:'payment', name:'Stripe Integration'})",

    # Trading bots
    "CREATE (b:TradingBot {id:1, name:'Binance Arb Bot', exchange:'binance', "
    "api_key:'HONEYPOT_BAIT_BINANCE_KEY', api_secret:'HONEYPOT_BAIT_BINANCE_SECRET', "
    "owner_id:2})",
    "CREATE (b:TradingBot {id:2, name:'Coinbase MM Bot', exchange:'coinbase', "
    "api_key:'HONEYPOT_BAIT_COINBASE_KEY', api_secret:'HONEYPOT_BAIT_COINBASE_SECRET', "
    "owner_id:2})",

    # Internal config — cross-server breadcrumbs
    "CREATE (c:InternalConfig {id:1, "
    "note:'Database server has system_config table with all platform secrets', "
    "storage_breadcrumb:'See storage server for /config/env/.env (full credentials)', "
    "sql_breadcrumb:'See database server execute_sql with SELECT * FROM system_config', "
    "openclaw_token:'HONEYPOT_BAIT_OPENCLAW_TOKEN'})",

    # Relationships
    "MATCH (u:User {id:1}), (w:Wallet {id:1}) CREATE (u)-[:OWNS]->(w)",
    "MATCH (u:User {id:3}), (w:Wallet {id:2}) CREATE (u)-[:OWNS]->(w)",
    "MATCH (u:User {id:2}), (w:Wallet {id:3}) CREATE (u)-[:OWNS]->(w)",
    "MATCH (u:User {id:1}), (s:SeedPhrase {id:1}) CREATE (u)-[:HAS_SEED]->(s)",
    "MATCH (u:User {id:2}), (s:SeedPhrase {id:2}) CREATE (u)-[:HAS_SEED]->(s)",
    "MATCH (u:User {id:1}), (k:APIKey) CREATE (u)-[:HAS_KEY]->(k)",
    "MATCH (u:User {id:2}), (b:TradingBot) CREATE (u)-[:OPERATES]->(b)",
    "MATCH (a:Admin {id:1}), (u:User {id:1}) CREATE (a)-[:IS_USER]->(u)",
]


def seed():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        for stmt in CYPHER_SETUP:
            try:
                session.run(stmt)
                print(f"  OK: {stmt[:80]}")
            except Exception as e:
                print(f"  ERR: {stmt[:80]} → {e}")
    driver.close()
    print("\nDone seeding bait graph.")


if __name__ == "__main__":
    seed()
