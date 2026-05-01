# i18n.py

LANG = "ja"

ATTACK_TYPE = {
    "ja": {
        "Brute Force": "ブルートフォース攻撃",
        "Admin Access": "管理画面アクセス試行",
        "Scanner": "スキャン行為",
        "Reconnaissance": "情報収集（偵察）",
        "Burst Access": "短時間アクセス集中",
        "Anomalous Timing": "異常時間帯アクセス",
        "Coordinated Brute Force": "協調ブルートフォース攻撃",
        "Suspicious Admin Timing": "不審な管理画面アクセス",
        "Automated Scanner": "自動スキャン",
        "Access Error Correlation": "アクセスエラー相関",
        "Suspicious Activity": "不審な挙動",
        "Normal": "通常のアクセス",
    }
}

ACTION = {
    "ja": {
        "Investigate immediately": "直ちに調査してください",
        "Monitor closely": "注意深く監視してください",
        "No immediate action required": "即時対応は不要です",
        "Check login attempts and consider temporary IP blocking": "ログイン試行を確認し、一時的なIPブロックを検討してください",
        "Review admin access logs and verify authentication controls": "管理画面アクセスログを確認し、認証設定を確認してください",
        "Review requested paths and consider rate limiting or blocking": "要求されたパスを確認し、レート制限またはブロックを検討してください",
        "Apply rate limiting or temporary IP blocking": "レート制限または一時的なIPブロックを適用してください",
        "Review access time patterns and user behavior": "アクセス時間帯とユーザー行動を確認してください",
        "Block source IP and review authentication logs immediately": "送信元IPをブロックし、認証ログを直ちに確認してください",
        "Verify admin activity and review privileged account usage": "管理者操作と特権アカウントの利用状況を確認してください",
        "Apply rate limiting and block scanning source if confirmed": "スキャン元と確認できる場合は、レート制限またはブロックを適用してください",
    }
}

UI_TEXT = {
    "ja": {
        "app_title": "AIセキュリティログ分析",
        "app_description": "ログファイルをアップロードして、不審なアクセスを分析します。",
        "choose_log_file": "ログファイルを選択",
        "use_sample_log": "サンプルログを使用",
        "analyze_file": "ファイルを解析",
        "history": "履歴",
        "load_history": "履歴を読み込む",
        "select_past_analysis": "過去の解析を選択",
        "load_selected_run": "選択した履歴を表示",
        "summary": "サマリー",
        "overview": "全体概要",
        "total_ips": "IP数",
        "high_risk": "高リスク",
        "medium_risk": "中リスク",
        "low_risk": "低リスク",
        "failed_requests": "失敗リクエスト数",
        "risk_distribution": "リスク分布",
        "top_risky_ips": "高リスクIP一覧",
        "time_series_analysis": "時系列分析",
        "detected_anomalies": "検知された異常",
        "no_anomalies": "異常は検知されませんでした。",
        "no_time_series": "時系列データがありません。",
        "security_summary": "セキュリティ概要",
        "filters": "フィルター",
        "filter_by_risk": "リスクレベルで絞り込み",
        "analysis_table": "分析結果",
        "export": "エクスポート",
        "download_csv": "CSVをダウンロード",
        "high_risk_ips": "高リスクIP",
        "no_high_risk_ips": "高リスクIPは検知されませんでした。",
        "timeline_analysis": "時系列分析",
        "ai_explanation": "AIによる補足説明",
        "loaded_run_id": "読み込んだ履歴ID",
        "timeline_chart_title": "アクセス時系列と異常ポイント",
    }
}


UI_TEXT["ja"].update({
    "summary_high_detected": "{count}件の高リスクIPが検出されました。",
    "summary_brute_force": "ブルートフォース攻撃の可能性があります。",
    "summary_admin_access": "管理画面への不審なアクセスが確認されています。",
    "summary_scanner": "スキャン行為または情報収集の可能性があります。",
    "summary_burst": "短時間にアクセスが集中しているIPがあります。",
    "summary_investigate": "⚠️ 直ちに調査してください。",
    "summary_medium_detected": "{count}件の中リスクIPが検出されました。",
    "summary_monitor": "現時点で緊急対応は不要ですが、継続的な監視を推奨します。",
    "summary_no_risk": "高リスクまたは中リスクの不審なアクセスは検出されませんでした。",
    "summary_no_action": "現時点で即時対応は不要です。",
})

UI_TEXT["ja"].update({
    "ip_detail": "IP詳細",
    "risk_level": "リスクレベル",
    "risk_score": "リスクスコア",
    "access_count": "アクセス数",
    "failed_count": "失敗数",
    "recommended_action": "推奨対応",
    "response_guide": "対応ガイド",
    "no_response_guide": "対応ガイドはありません。",
    "immediate_actions": "直ちに行う対応",
    "short_term_actions": "短期対応",
    "long_term_actions": "長期対応",
    "escalation": "エスカレーション",
    "advanced_commands": "上級者向けコマンド",
    "technical_details": "技術的詳細",
    "suspicious_paths": "不審なパス",
    "signals": "検知シグナル",
    "status_counts": "ステータスコード数",
    "selected_ip_timeline": "選択IPの時系列",
    "no_timeline_data_history": "この履歴には時系列データがありません。",
    "no_timeline_data_ip": "このIPの時系列データはありません。",
    "selected_ip_anomalies": "選択IPの異常",
    "no_anomalies_ip": "このIPでは異常は検知されませんでした。",
    "ai_mode": "AIモード",
    "ai_mode_local": "AIモード: ローカル",
    "ai_mode_off": "AIモード: オフ",
    "clear_cache": "キャッシュをクリア",
    "analyzing_ip": "{ip} を分析中...",
    "cache_size": "キャッシュ数",
    "ai_guard_log": "AIガードログ",
    "no_ai_guard_issues": "AIガードの問題は検出されませんでした。",
    "ai_guard_sanitized": "AIガードが {count} 件の項目をサニタイズしました。",
    "immediate_actions": "直ちに行う対応",
    "advanced_commands": "上級者向けコマンド",
    "choose_log_file": "ログファイルを選択"
})

UI_TEXT["ja"].update({
    "chart_access_count": "アクセス数",
    "chart_failed_count": "失敗数",
    "chart_anomaly": "異常",
    "chart_time": "時刻",
    "chart_count": "件数",
    "chart_reason": "理由",
})

UI_TEXT["ja"].update({
    "col_time": "時刻",
    "col_ip": "IP",
    "col_access_count": "アクセス数",
    "col_failed_count": "失敗数",
    "col_failure_rate": "失敗率",
    "col_anomaly_reason": "異常理由",
})
UI_TEXT["ja"].update({
    "col_priority_score": "優先度",
    "col_risk_score": "スコア",
    "col_failure_rate": "失敗率",
})
UI_TEXT["ja"].update({
    "col_event": "検知内容",
})
UI_TEXT["ja"].update({
    "reason_high_failure": "失敗率が高い（{rate}%）",
    "reason_multiple_suspicious": "複数の不審な挙動が検出されました",
})


def t(key: str, **kwargs) -> str:
    text = UI_TEXT[LANG].get(key, key)
    return text.format(**kwargs) if kwargs else text

def translate_attack_type(attack_type: str) -> str:
    if not attack_type:
        return ""

    types = attack_type.split(", ")
    return " / ".join(
        ATTACK_TYPE[LANG].get(item, item)
        for item in types
    )


def translate_action(action: str) -> str:
    if not action:
        return ""

    actions = action.split(" / ")
    return " / ".join(
        ACTION[LANG].get(item, item)
        for item in actions
    )

def translate_anomaly_reason(reason: str) -> str:
    if not reason:
        return ""

    parts = reason.split(" / ")
    results = []

    for p in parts:
        if "High failure rate" in p:
            # 数値抽出
            import re
            match = re.search(r"\((\d+)%\)", p)
            rate = match.group(1) if match else "?"
            results.append(t("reason_high_failure", rate=rate))

        elif "Multiple suspicious activities" in p:
            results.append(t("reason_multiple_suspicious"))

        else:
            results.append(p)

    return " / ".join(results)