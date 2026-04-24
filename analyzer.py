def get_risk_level(score):
    if score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    return "LOW"


def analyze_log_lines(lines):
    ip_counts = {}
    failed_counts = {}
    ip_scores = {}
    path_counts = {}
    suspicious_path_by_ip = {}
    status_counts = {}
    reasons_by_ip = {}

    SUSPICIOUS_PATHS = [
        "/admin",
        "/login",
        "/phpmyadmin",
        "/wp-admin",
        "/.env",
        "/config",
        "/backup"
    ]

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) != 4:
            continue

        ip = parts[0]
        method = parts[1]
        url = parts[2]
        status = parts[3]

        if ip not in ip_counts:
            ip_counts[ip] = 0
            failed_counts[ip] = 0
            ip_scores[ip] = 0
            path_counts[ip] = {}
            suspicious_path_by_ip[ip] = []
            status_counts[ip] = {}
            reasons_by_ip[ip] = []

        ip_counts[ip] += 1

        if url not in path_counts[ip]:
            path_counts[ip][url] = 0
        path_counts[ip][url] += 1

        if status not in status_counts[ip]:
            status_counts[ip][status] = 0
        status_counts[ip][status] += 1

        if status in ["401", "403"]:
            failed_counts[ip] += 1
            ip_scores[ip] += 1

        if url in SUSPICIOUS_PATHS:
            if url not in suspicious_path_by_ip[ip]:
                suspicious_path_by_ip[ip].append(url)

    for ip in ip_counts:
        access_count = ip_counts[ip]
        failed_count = failed_counts[ip]
        failure_rate = failed_count / access_count if access_count > 0 else 0

        if failure_rate >= 0.5:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("high failure rate")

        if len(suspicious_path_by_ip[ip]) >= 2:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("multiple suspicious paths")

        if "/login" in path_counts[ip] and path_counts[ip]["/login"] >= 5:
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("repeated login attempts")

        if "404" in status_counts[ip] and status_counts[ip]["404"] >= 5:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("many 404 responses")

        if "/admin" in suspicious_path_by_ip[ip]:
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("admin access attempts")

    results = []

    for ip in ip_counts:
        score = ip_scores[ip]
        level = get_risk_level(score)

        results.append({
            "ip": ip,
            "risk_level": level,
            "risk_score": score,
            "access_count": ip_counts[ip],
            "failed_count": failed_counts[ip],
            "suspicious_paths": suspicious_path_by_ip[ip],
            "status_counts": status_counts[ip],
            "reasons": reasons_by_ip[ip]
        })

    return results


def analyze_log_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    return analyze_log_lines(lines)