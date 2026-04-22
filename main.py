ip_counts = {}
failed_counts = {}
ip_scores = {}
suspicious_events = []
path_counts = {}
suspicious_path_by_ip ={}
status_counts = {}
reasons_by_ip = {}

SUSPICIOUS_PATHS = ["/admin","/login","/phpmyadmin","/wp-admin","/.env","/config","/backup"]

with open("data/sample.log", encoding="utf-8") as f:
	for line in f:
		line = line.strip()

		# 空行を無視
		if not line:
			continue
		
		#コメント行を無視
		if line.startswith("#"):
			continue

		parts = line.split()

		#4項目でない行を無視
		if len(parts) != 4:
			continue

		#print(parts)
		ip = parts[0]
		method = parts[1]
		url = parts[2]
		status = parts[3]


		#初期化
		if ip not in ip_counts:
			ip_counts[ip] = 0
			failed_counts[ip] = 0
			ip_scores[ip] = 0
			path_counts[ip]= {}
			suspicious_path_by_ip[ip]= []
			status_counts[ip] = {}
			reasons_by_ip[ip] = []
			
			
		#総アクセス数
		ip_counts[ip] += 1

		#URLごとの回数
		if url not in path_counts[ip]:
			path_counts[ip][url] = 0
		path_counts[ip][url] +=1

		#ステータスごとの回数
		if status not in status_counts[ip]:
			status_counts[ip][status] = 0
		status_counts[ip][status] += 1

			

		#失敗
		#ステータスコード検知
		if status in ["401", "403"]:
			failed_counts[ip] += 1
			ip_scores[ip] += 1
			suspicious_events.append(f"[WARN] suspicious access: {ip} url={url} status={status}")
		
		#suspicious pathを記録
		if url in SUSPICIOUS_PATHS:
			if url not in suspicious_path_by_ip[ip]:
				suspicious_path_by_ip[ip].append(url)


#追加ルール
for ip in ip_counts:	
	access_count = ip_counts[ip]
	failed_count = failed_counts[ip]
	failure_rate = failed_count / access_count if access_count > 0 else 0

	#失敗率が高い
	if failure_rate >= 0.5:
		ip_scores[ip] +=2
		reasons_by_ip[ip].append("high failure rate")
		suspicious_events.append(f"[MEDIUM] {ip} has high failure rate : {failure_rate: .2f}")

	#危険パスが複数ある
	if len(suspicious_path_by_ip[ip]) >=2:
		ip_scores[ip] +=2
		reasons_by_ip[ip].append("multiple suspicious paths")
		suspicious_events.append(f"[MEDIUM] {ip} accessed multiple suspicious paths: {suspicious_path_by_ip[ip]}")

	#ログイン連打
	if "/login" in path_counts[ip] and path_counts[ip]["/login"] >=5:
		ip_scores[ip] += 3
		reasons_by_ip[ip].append("repeated login attempts")
		suspicious_events.append(f"[HIGH] {ip} repeated login ")
	# 404多発
	if "404" in status_counts[ip] and status_counts[ip]["404"] >= 5:
		ip_scores[ip] +=2
		reasons_by_ip[ip].append("many 404 responses")
		suspicious_events.append(f"[MEDIUM] {ip} generated many 404 responses: {status_counts[ip]['404']} times")
	#admin アクセス
	if"/admin" in suspicious_path_by_ip[ip]:
		ip_scores[ip] += 3
		reasons_by_ip[ip].append("Admin Access Attempts")
		suspicious_events.append(f"[HIGH] HIGH RISK: {ip} tried to access admin page")
		

#High Risk Print
print("\n --- Suspicious Events ---")
for event in suspicious_events:
	print(event)

print("\n --- Risk Score ---")
for ip, score in ip_scores.items():
	if score >=8:
		print(f"[HIGH] {ip} score={score}")
	elif score >= 4:
		print(f"[MEDIUM] {ip} score={score}")
	else:
		print(f"[LOW] {ip} score={score}")


#集計表示
print("\n--- IP count ---")
for ip, count in ip_counts.items():
	print(f"{ip}: {count}times")

print("\n --- Failed Attempts ---")
for ip, count in failed_counts.items():
	print(f"{ip}: {count} failures")

print("\n --- Suspicious Paths ---")
for ip, paths in suspicious_path_by_ip.items():
	print(f"{ip}: {paths}")

print("\n --- Status Counts ---")
for ip, count in status_counts.items():
	print(f"{ip}: {count}")

print("\n--- Final Analysis ---")
for ip in ip_counts:
    score = ip_scores[ip]

    if score >= 8:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    print(f"\nIP: {ip}")
    print(f"  Risk Level       : {level}")
    print(f"  Risk Score       : {score}")
    print(f"  Access Count     : {ip_counts[ip]}")
    print(f"  Failed Count     : {failed_counts[ip]}")
    print(f"  Suspicious Paths : {suspicious_path_by_ip[ip]}")
    print(f"  Status Counts    : {status_counts[ip]}")
    print(f"  Reasons          : {reasons_by_ip[ip]}")
