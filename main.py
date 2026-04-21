ip_counts = {}

with open("data/sample.log", encoding="utf-8") as f:
	for line in f:
		parts = line.strip().split()
		#print(parts)
		ip = parts[0]
		url = parts[5]
		status = parts[7]

		#回数カウント
		if ip in ip_counts:
			ip_counts[ip] += 1
		else:
			ip_counts[ip] = 1

		#ステータスコード検知
		if status in ["401", "403"]:
			print(f"suspicious access: {ip} url={url} status={status}")

#集計表示
print("\n--- IP count ---")
for ip, count in ip_counts.items():
	print(f"{ip}: {count}回")

