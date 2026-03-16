import os
import shlex


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./data.db")


def get_environment() -> str:
    return os.getenv("ASM_ENV", "dev")


def get_queue_backend() -> str:
    return os.getenv("ASM_QUEUE_BACKEND", "db")


def get_redis_url() -> str:
    return os.getenv("REDIS_URL", "redis://localhost:6379/0")


def get_scanner_timeout() -> int:
    return int(os.getenv("ASM_SCANNER_TIMEOUT", "300"))


def get_scan_retries() -> int:
    return int(os.getenv("ASM_SCAN_RETRIES", "3"))


def get_scan_retry_backoff() -> float:
    return float(os.getenv("ASM_SCAN_RETRY_BACKOFF", "1.0"))


def get_scan_retry_max_backoff() -> float:
    return float(os.getenv("ASM_SCAN_RETRY_MAX_BACKOFF", "10.0"))


def get_scan_concurrency() -> int:
    return int(os.getenv("ASM_SCAN_CONCURRENCY", "5"))


def get_scan_rate() -> float:
    return float(os.getenv("ASM_SCAN_RATE", "0"))


def get_scan_healthcheck_enabled() -> bool:
    return os.getenv("ASM_SCAN_HEALTHCHECK", "true").lower() == "true"


def get_scan_isolation() -> str:
    return os.getenv("ASM_SCAN_ISOLATION", "host").lower()


def get_scan_container_image(tool: str) -> str | None:
    tool_key = f"ASM_{tool.upper()}_IMAGE"
    return os.getenv(tool_key) or os.getenv("ASM_SCAN_CONTAINER_IMAGE")


def get_scan_container_network() -> str:
    return os.getenv("ASM_SCAN_CONTAINER_NETWORK", "")


def get_scan_container_workdir() -> str:
    return os.getenv("ASM_SCAN_CONTAINER_WORKDIR", "/work")


def get_scan_container_args() -> list[str]:
    value = os.getenv("ASM_SCAN_CONTAINER_ARGS", "")
    if not value:
        return []
    return shlex.split(value)


def get_scan_workdir() -> str | None:
    return os.getenv("ASM_SCAN_WORKDIR")


def get_allow_stub_scans() -> bool:
    default = "true" if get_environment() == "dev" else "false"
    return os.getenv("ASM_ALLOW_STUBS", default).lower() == "true"


def get_scanner_bin(name: str, default: str) -> str:
    env_key = f"ASM_{name.upper()}_BIN"
    return os.getenv(env_key, default)


def get_scanner_args(name: str) -> list[str]:
    env_key = f"ASM_{name.upper()}_ARGS"
    value = os.getenv(env_key, "")
    if not value:
        return []
    return shlex.split(value)


def get_httpx_tech_detect() -> bool:
    return os.getenv("ASM_HTTPX_TECH_DETECT", "true").lower() == "true"


def get_jwt_secret() -> str:
    secret = os.getenv("ASM_JWT_SECRET", "")
    if not secret:
        env = get_environment()
        if env in ("prod", "production"):
            raise RuntimeError(
                "ASM_JWT_SECRET environment variable is required in production. "
                "Run: python3 -c [import secrets; print(secrets.token_hex(32))]"
            )
        # Dev-only fallback — never safe for production
        secret = "dev-only-insecure-change-me-set-ASM_JWT_SECRET"
    if len(secret) < 32 and get_environment() in ("prod", "production"):
        raise RuntimeError(
            f"ASM_JWT_SECRET too short ({len(secret)} chars). "
            "Minimum 32 characters required."
        )
    return secret


def get_jwt_exp_minutes() -> int:
    return int(os.getenv("ASM_JWT_EXP_MINUTES", "120"))


def get_rate_limit() -> str:
    return os.getenv("ASM_RATE_LIMIT", "60/minute")


def get_cloud_providers() -> list[str]:
    value = os.getenv("ASM_CLOUD_PROVIDERS", "aws,gcp,azure")
    return [provider.strip() for provider in value.split(",") if provider.strip()]


def get_cloud_public_check() -> bool:
    return os.getenv("ASM_CLOUD_PUBLIC_CHECK", "true").lower() == "true"


def get_ct_enabled() -> bool:
    return os.getenv("ASM_CT_ENABLED", "true").lower() == "true"


def get_ct_max() -> int:
    return int(os.getenv("ASM_CT_MAX", "500"))


def get_certspotter_enabled() -> bool:
    return os.getenv("ASM_CERTSPOTTER_ENABLED", "true").lower() == "true"


def get_certspotter_token() -> str | None:
    return os.getenv("ASM_CERTSPOTTER_TOKEN")


def get_certspotter_limit() -> int:
    return int(os.getenv("ASM_CERTSPOTTER_LIMIT", "500"))


def get_katana_depth() -> int:
    return int(os.getenv("ASM_KATANA_DEPTH", "2"))


def get_endpoint_limit() -> int:
    return int(os.getenv("ASM_ENDPOINT_LIMIT", "500"))


def get_gau_limit() -> int:
    return int(os.getenv("ASM_GAU_LIMIT", "500"))


def get_wayback_limit() -> int:
    return int(os.getenv("ASM_WAYBACK_LIMIT", "500"))


def get_intel_host_limit() -> int:
    return int(os.getenv("ASM_INTEL_HOST_LIMIT", "500"))


def get_github_org() -> str | None:
    return os.getenv("ASM_GITHUB_ORG")


def get_github_repo() -> str | None:
    return os.getenv("ASM_GITHUB_REPO")


def get_github_token() -> str | None:
    return os.getenv("ASM_GITHUB_TOKEN")


def get_github_search_query() -> str | None:
    return os.getenv("ASM_GITHUB_SEARCH_QUERY")


def get_github_search_limit() -> int:
    return int(os.getenv("ASM_GITHUB_SEARCH_LIMIT", "50"))


def get_gitlab_base() -> str:
    return os.getenv("ASM_GITLAB_BASE", "https://gitlab.com")


def get_gitlab_token() -> str | None:
    return os.getenv("ASM_GITLAB_TOKEN")


def get_gitlab_search_query() -> str | None:
    return os.getenv("ASM_GITLAB_SEARCH_QUERY")


def get_gitlab_search_limit() -> int:
    return int(os.getenv("ASM_GITLAB_SEARCH_LIMIT", "50"))


def get_bitbucket_command() -> str | None:
    return os.getenv("ASM_BITBUCKET_CMD")


def get_bitbucket_search_query() -> str | None:
    return os.getenv("ASM_BITBUCKET_SEARCH_QUERY")


def get_bitbucket_search_limit() -> int:
    return int(os.getenv("ASM_BITBUCKET_SEARCH_LIMIT", "50"))


def get_public_repo_url() -> str | None:
    return os.getenv("ASM_PUBLIC_REPO_URL")


def get_dns_brute_command() -> str | None:
    return os.getenv("ASM_DNS_BRUTE_CMD")


def get_dns_brute_wordlist() -> str | None:
    return os.getenv("ASM_DNS_BRUTE_WORDLIST")


def get_dns_brute_words() -> str:
    return os.getenv("ASM_DNS_BRUTE_WORDS", "admin,dev,api,staging,test,internal")


def get_dns_brute_limit() -> int:
    return int(os.getenv("ASM_DNS_BRUTE_LIMIT", "500"))


def get_puredns_command() -> str | None:
    return os.getenv("ASM_PUREDNS_CMD")


def get_massdns_command() -> str | None:
    return os.getenv("ASM_MASSDNS_CMD")


def get_reverse_ip_command() -> str | None:
    return os.getenv("ASM_REVERSE_IP_CMD")


def get_reverse_ip_limit() -> int:
    return int(os.getenv("ASM_REVERSE_IP_LIMIT", "25"))


def get_reverse_ip_include_external() -> bool:
    return os.getenv("ASM_REVERSE_IP_INCLUDE_EXTERNAL", "false").lower() == "true"


def get_shodan_command() -> str | None:
    return os.getenv("ASM_SHODAN_CMD")


def get_securitytrails_command() -> str | None:
    return os.getenv("ASM_SECURITYTRAILS_CMD")


def get_cloudflare_command() -> str | None:
    return os.getenv("ASM_CLOUDFLARE_CMD")


def get_dnsdumpster_command() -> str | None:
    return os.getenv("ASM_DNSDUMPSTER_CMD")


def get_asn_command() -> str | None:
    return os.getenv("ASM_ASN_CMD")


def get_hosting_command() -> str | None:
    return os.getenv("ASM_HOSTING_CMD")


def get_geoip_command() -> str | None:
    return os.getenv("ASM_GEOIP_CMD")


def get_asn_ranges_command() -> str | None:
    return os.getenv("ASM_ASN_RANGES_CMD")


def get_asn_discovery_enabled() -> bool:
    return os.getenv("ASM_ASN_DISCOVERY_ENABLED", "true").lower() == "true"


def get_asn_range_limit() -> int:
    return int(os.getenv("ASM_ASN_RANGE_LIMIT", "50"))


def get_ip_range_scan_limit() -> int:
    return int(os.getenv("ASM_IP_RANGE_SCAN_LIMIT", "256"))


def get_bucket_wordlist() -> str | None:
    return os.getenv("ASM_BUCKET_WORDLIST")


def get_bucket_words() -> str:
    return os.getenv(
        "ASM_BUCKET_WORDS",
        "backup,backups,static,cdn,assets,media,files,uploads,private,public,logs,archive,staging,dev,prod,test",
    )


def get_bucket_limit() -> int:
    return int(os.getenv("ASM_BUCKET_LIMIT", "500"))


def get_bucket_probe_timeout() -> int:
    return int(os.getenv("ASM_BUCKET_PROBE_TIMEOUT", "10"))


def get_js_max_bytes() -> int:
    return int(os.getenv("ASM_JS_MAX_BYTES", "1048576"))


def get_js_subdomain_limit() -> int:
    return int(os.getenv("ASM_JS_SUBDOMAIN_LIMIT", "500"))


def get_permutation_words() -> str:
    return os.getenv(
        "ASM_PERMUTATION_WORDS",
        "dev,test,staging,stage,qa,prod,internal,api,admin,old,new,edge,cdn,private,public,backup",
    )


def get_permutation_limit() -> int:
    return int(os.getenv("ASM_PERMUTATION_LIMIT", "1000"))


def get_recursive_enabled() -> bool:
    return os.getenv("ASM_RECURSIVE_ENABLED", "true").lower() == "true"


def get_recursive_max_depth() -> int:
    return int(os.getenv("ASM_RECURSIVE_MAX_DEPTH", "2"))


def get_recursive_max_new() -> int:
    return int(os.getenv("ASM_RECURSIVE_MAX_NEW", "2000"))


def get_cloud_enum_enabled() -> bool:
    return os.getenv("ASM_CLOUD_ENUM_ENABLED", "true").lower() == "true"


def get_worker_mode() -> str:
    return os.getenv("ASM_WORKER_MODE", "all").lower()


def get_js_url_limit() -> int:
    return int(os.getenv("ASM_JS_URL_LIMIT", "200"))


def get_secret_scan_limit() -> int:
    return int(os.getenv("ASM_SECRET_SCAN_LIMIT", "50"))


def get_secret_max_bytes() -> int:
    return int(os.getenv("ASM_SECRET_MAX_BYTES", "1048576"))


def get_secret_regex() -> str | None:
    return os.getenv("ASM_SECRET_REGEX")


def get_ffuf_wordlist() -> str | None:
    return os.getenv("ASM_FFUF_WORDLIST")


def get_ffuf_words() -> str:
    return os.getenv(
        "ASM_FFUF_WORDS",
        "admin,backup,.env,debug,graphql,api,internal,staging,old,dev,config",
    )


def get_ffuf_limit() -> int:
    return int(os.getenv("ASM_FFUF_LIMIT", "200"))


def get_ffuf_rate() -> int:
    return int(os.getenv("ASM_FFUF_RATE", "50"))


def get_ffuf_timeout() -> int:
    return int(os.getenv("ASM_FFUF_TIMEOUT", "20"))


def get_ffuf_match_codes() -> str:
    return os.getenv("ASM_FFUF_MATCH_CODES", "200,204,301,302,307,401,403")


def get_dirsearch_wordlist() -> str | None:
    return os.getenv("ASM_DIRSEARCH_WORDLIST")


def get_dirsearch_words() -> str:
    return os.getenv("ASM_DIRSEARCH_WORDS", get_ffuf_words())


def get_dirsearch_limit() -> int:
    return int(os.getenv("ASM_DIRSEARCH_LIMIT", "200"))


def get_dirsearch_rate() -> int:
    return int(os.getenv("ASM_DIRSEARCH_RATE", "50"))


def get_dirsearch_timeout() -> int:
    return int(os.getenv("ASM_DIRSEARCH_TIMEOUT", "20"))


def get_risk_increase_threshold() -> float:
    return float(os.getenv("ASM_RISK_INCREASE_THRESHOLD", "10.0"))


def get_oauth_client_id(provider: str) -> str | None:
    key = f"ASM_OAUTH_{provider.upper()}_CLIENT_ID"
    return os.getenv(key)


def get_oauth_client_secret(provider: str) -> str | None:
    key = f"ASM_OAUTH_{provider.upper()}_CLIENT_SECRET"
    return os.getenv(key)


def get_oauth_redirect_uri(provider: str) -> str | None:
    key = f"ASM_OAUTH_{provider.upper()}_REDIRECT_URI"
    return os.getenv(key)


def get_stripe_secret_key() -> str | None:
    return os.getenv("ASM_STRIPE_SECRET_KEY")


def get_stripe_webhook_secret() -> str | None:
    return os.getenv("ASM_STRIPE_WEBHOOK_SECRET")


def get_stripe_success_url() -> str:
    return os.getenv("ASM_STRIPE_SUCCESS_URL", "http://localhost:3000/billing/success")


def get_stripe_cancel_url() -> str:
    return os.getenv("ASM_STRIPE_CANCEL_URL", "http://localhost:3000/billing/cancel")


def get_stripe_default_price_id() -> str | None:
    return os.getenv("ASM_STRIPE_DEFAULT_PRICE_ID")


def get_pdns_command() -> str | None:
    return os.getenv("ASM_PDNS_CMD")


def get_censys_command() -> str | None:
    return os.getenv("ASM_CENSYS_CMD")


def get_asset_scan_interval_hours() -> int:
    return int(os.getenv("ASM_ASSET_SCAN_INTERVAL_HOURS", "6"))


def get_vuln_scan_interval_days() -> int:
    return int(os.getenv("ASM_VULN_SCAN_INTERVAL_DAYS", "1"))


def get_deep_scan_day() -> int:
    return int(os.getenv("ASM_DEEP_SCAN_DAY", "1"))


def get_deep_scan_hour() -> int:
    return int(os.getenv("ASM_DEEP_SCAN_HOUR", "2"))


def get_deep_scan_minute() -> int:
    return int(os.getenv("ASM_DEEP_SCAN_MINUTE", "0"))


def get_deep_scan_interval_days() -> int:
    return int(os.getenv("ASM_DEEP_SCAN_INTERVAL_DAYS", "7"))


def get_alerts_enabled() -> bool:
    return os.getenv("ASM_ALERTS_ENABLED", "true").lower() == "true"


def get_slack_webhook() -> str | None:
    return os.getenv("ASM_SLACK_WEBHOOK")


def get_discord_webhook() -> str | None:
    return os.getenv("ASM_DISCORD_WEBHOOK")


def get_alert_webhook() -> str | None:
    return os.getenv("ASM_ALERT_WEBHOOK")


def get_email_from() -> str | None:
    return os.getenv("ASM_EMAIL_FROM")


def get_email_to() -> str | None:
    return os.getenv("ASM_EMAIL_TO")


def get_smtp_host() -> str | None:
    return os.getenv("ASM_SMTP_HOST")


def get_smtp_port() -> int:
    return int(os.getenv("ASM_SMTP_PORT", "587"))


def get_smtp_username() -> str | None:
    return os.getenv("ASM_SMTP_USERNAME")


def get_smtp_password() -> str | None:
    return os.getenv("ASM_SMTP_PASSWORD")


def get_smtp_tls() -> bool:
    return os.getenv("ASM_SMTP_TLS", "true").lower() == "true"


def get_jira_enabled() -> bool:
    return os.getenv("ASM_JIRA_ENABLED", "false").lower() == "true"


def get_jira_base() -> str | None:
    return os.getenv("ASM_JIRA_BASE")


def get_jira_email() -> str | None:
    return os.getenv("ASM_JIRA_EMAIL")


def get_jira_token() -> str | None:
    return os.getenv("ASM_JIRA_TOKEN")


def get_jira_project() -> str | None:
    return os.getenv("ASM_JIRA_PROJECT")


def get_jira_issue_type() -> str:
    return os.getenv("ASM_JIRA_ISSUE_TYPE", "Bug")


# ---------------------------------------------------------------------------
# Enhanced notification channels
# ---------------------------------------------------------------------------

def get_pagerduty_routing_key() -> str | None:
    return os.getenv("ASM_PAGERDUTY_ROUTING_KEY")


def get_pagerduty_enabled() -> bool:
    return bool(get_pagerduty_routing_key())


def get_ms_teams_webhook() -> str | None:
    return os.getenv("ASM_MS_TEAMS_WEBHOOK")


def get_opsgenie_api_key() -> str | None:
    return os.getenv("ASM_OPSGENIE_API_KEY")


def get_opsgenie_enabled() -> bool:
    return bool(get_opsgenie_api_key())


def get_telegram_bot_token() -> str | None:
    return os.getenv("ASM_TELEGRAM_BOT_TOKEN")


def get_telegram_chat_id() -> str | None:
    return os.getenv("ASM_TELEGRAM_CHAT_ID")


def get_alert_cooldown_seconds() -> int:
    return int(os.getenv("ASM_ALERT_COOLDOWN_SECONDS", "300"))


def get_alert_severity_threshold() -> str:
    return os.getenv("ASM_ALERT_SEVERITY_THRESHOLD", "low")


def get_alert_dedup_window_hours() -> int:
    return int(os.getenv("ASM_ALERT_DEDUP_WINDOW_HOURS", "24"))


# ---------------------------------------------------------------------------
# Vulnerability scanner config
# ---------------------------------------------------------------------------

def get_nuclei_concurrency() -> int:
    return int(os.getenv("ASM_NUCLEI_CONCURRENCY", "25"))


def get_nuclei_rate_limit() -> int:
    return int(os.getenv("ASM_NUCLEI_RATE_LIMIT", "150"))


def get_nuclei_bulk_size() -> int:
    return int(os.getenv("ASM_NUCLEI_BULK_SIZE", "50"))


def get_nuclei_timeout() -> int:
    return int(os.getenv("ASM_NUCLEI_TIMEOUT", "5"))


def get_nvd_api_key() -> str | None:
    return os.getenv("ASM_NVD_API_KEY")


def get_vuln_dedup_enabled() -> bool:
    return os.getenv("ASM_VULN_DEDUP_ENABLED", "true").lower() == "true"


def get_false_positive_auto_tag() -> bool:
    return os.getenv("ASM_FP_AUTO_TAG", "false").lower() == "true"


def get_exploit_db_enabled() -> bool:
    return os.getenv("ASM_EXPLOIT_DB_ENABLED", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Distributed worker config
# ---------------------------------------------------------------------------

def get_worker_id() -> str:
    import socket
    return os.getenv("ASM_WORKER_ID", socket.gethostname())


def get_worker_max_parallel_scans() -> int:
    return int(os.getenv("ASM_WORKER_MAX_PARALLEL", "3"))


def get_worker_heartbeat_interval() -> int:
    return int(os.getenv("ASM_WORKER_HEARTBEAT_SECONDS", "30"))


def get_worker_stale_threshold_seconds() -> int:
    return int(os.getenv("ASM_WORKER_STALE_SECONDS", "120"))


def get_worker_specialization() -> list[str]:
    raw = os.getenv("ASM_WORKER_SPECIALIZATION", "")
    return [s.strip() for s in raw.split(",") if s.strip()] if raw else []


def get_scan_chunk_size() -> int:
    return int(os.getenv("ASM_SCAN_CHUNK_SIZE", "20"))


def get_scan_result_ttl_hours() -> int:
    return int(os.getenv("ASM_SCAN_RESULT_TTL_HOURS", "168"))


# ---------------------------------------------------------------------------
# Threat Intelligence API keys
# ---------------------------------------------------------------------------

def get_abuseipdb_api_key() -> str | None:
    return os.getenv("ASM_ABUSEIPDB_API_KEY")

def get_virustotal_api_key() -> str | None:
    return os.getenv("ASM_VIRUSTOTAL_API_KEY")

def get_greynoise_api_key() -> str | None:
    return os.getenv("ASM_GREYNOISE_API_KEY")

def get_otx_api_key() -> str | None:
    return os.getenv("ASM_OTX_API_KEY")

def get_shodan_api_key() -> str | None:
    return os.getenv("ASM_SHODAN_API_KEY")

def get_ti_cache_ttl() -> int:
    return int(os.getenv("ASM_TI_CACHE_TTL", "3600"))

def get_ti_enabled() -> bool:
    return os.getenv("ASM_TI_ENABLED", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Attack path engine config
# ---------------------------------------------------------------------------

def get_attack_path_max_paths() -> int:
    return int(os.getenv("ASM_ATTACK_PATH_MAX", "20"))

def get_attack_path_max_hops() -> int:
    return int(os.getenv("ASM_ATTACK_PATH_MAX_HOPS", "7"))

def get_attack_path_min_score() -> float:
    return float(os.getenv("ASM_ATTACK_PATH_MIN_SCORE", "15.0"))

# ---------------------------------------------------------------------------
# SIEM / Export config
# ---------------------------------------------------------------------------

def get_splunk_hec_url() -> str | None:
    return os.getenv("ASM_SPLUNK_HEC_URL")

def get_splunk_hec_token() -> str | None:
    return os.getenv("ASM_SPLUNK_HEC_TOKEN")

def get_elastic_url() -> str | None:
    return os.getenv("ASM_ELASTIC_URL")

def get_siem_webhook_url() -> str | None:
    return os.getenv("ASM_SIEM_WEBHOOK_URL")

def get_siem_format() -> str:
    return os.getenv("ASM_SIEM_FORMAT", "json")

def get_siem_auto_export_hours() -> int:
    return int(os.getenv("ASM_SIEM_AUTO_EXPORT_HOURS", "1"))

def get_siem_export_enabled() -> bool:
    return os.getenv("ASM_SIEM_EXPORT_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Crawler config
# ---------------------------------------------------------------------------

def get_crawl_strategies() -> str:
    return os.getenv("ASM_CRAWL_STRATEGIES", "katana,gau,passive,js,robots")

def get_crawl_passive_timeout() -> int:
    return int(os.getenv("ASM_CRAWL_PASSIVE_TIMEOUT", "15"))

# ---------------------------------------------------------------------------
# Circuit breaker config
# ---------------------------------------------------------------------------

def get_cb_failure_threshold() -> int:
    return int(os.getenv("ASM_CB_FAILURE_THRESHOLD", "5"))

def get_cb_recovery_timeout() -> float:
    return float(os.getenv("ASM_CB_RECOVERY_TIMEOUT", "60"))
