import subprocess
import re
import csv
import matplotlib.pyplot as plt


def run_benchmark():
    print("[HỆ THỐNG] Đang chạy pqtool.exe benchmark để thu thập dữ liệu...")

    # Gọi file exe và lấy dữ liệu xuất ra màn hình
    try:
        result = subprocess.run(['./pqtool.exe', 'benchmark'], capture_output=True, text=True, encoding='utf-8')
        output = result.stdout
        print(output)  # In ra màn hình để bạn theo dõi
    except Exception as e:
        print(f"[LỖI] Không thể chạy pqtool.exe: {e}")
        return

    # Khởi tạo cấu trúc lưu dữ liệu
    data = []

    # Dùng Regular Expression (Regex) để bóc tách số liệu
    algo_blocks = output.split("--- Thuật toán: ")

    for block in algo_blocks[1:]:
        lines = block.split("\n")
        algo_name = lines[0].strip(" -")

        mean, median, std_dev, ci_lower, ci_upper = 0, 0, 0, 0, 0

        for line in lines:
            if "Mean" in line:
                mean = float(re.search(r"Mean.*?:\s*([\d.e+-]+)", line).group(1))
            elif "Median" in line:
                median = float(re.search(r"Median.*?:\s*([\d.e+-]+)", line).group(1))
            elif "Std Dev" in line:
                std_dev = float(re.search(r"Std Dev.*?:\s*([\d.e+-]+)", line).group(1))
            elif "95% Confidence Interval" in line:
                match = re.search(r"\[([\d.e+-]+),\s*([\d.e+-]+)\]", line)
                ci_lower = float(match.group(1))
                ci_upper = float(match.group(2))

        data.append({
            "Algorithm": algo_name,
            "Mean": mean,
            "Median": median,
            "Std Dev": std_dev,
            "CI_Lower": ci_lower,
            "CI_Upper": ci_upper
        })

    # 1. Ghi dữ liệu thống kê ra file CSV
    csv_filename = "benchmark_report.csv"
    with open(csv_filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Algorithm", "Mean", "Median", "Std Dev", "CI_Lower", "CI_Upper"])
        writer.writeheader()
        writer.writerows(data)
    print(f"[OK] Đã xuất file số liệu: {csv_filename}")

    # 2. Tự động vẽ đồ thị và lưu thành file ảnh
    print("[HỆ THỐNG] Đang tiến hành vẽ đồ thị hiệu năng...")
    algos = [d["Algorithm"] for d in data]
    means = [d["Mean"] * 100000 for d in data]  # Nhân 100,000 để khử e-05 giúp đồ thị đẹp hơn
    std_devs = [d["Std Dev"] * 100000 for d in data]

    plt.figure(figsize=(8, 6))
    # Vẽ biểu đồ cột kèm thanh sai số Error Bars (yerr)
    bars = plt.bar(algos, means, yerr=std_devs, capsize=8, color=['#3498db', '#e74c3c', '#2ecc71'], edgecolor='black')

    plt.title("So sánh độ trễ thực thi giữa các thuật toán PQC", fontsize=14, fontweight='bold')
    plt.ylabel("Độ trễ trung bình (x10^-5 ms/op)", fontsize=12)
    plt.xlabel("Thuật toán mật mã", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Hiển thị số liệu trên đầu mỗi cột
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2.0, yval + (max(means) * 0.02), f"{yval:.2f}", ha='center',
                 va='bottom', fontweight='bold')

    plt.tight_layout()
    chart_filename = "pqc_latency_chart.png"
    plt.savefig(chart_filename, dpi=300)
    print(f"[OK] Đã vẽ và lưu đồ thị tại: {chart_filename}")
    print(
        "\n===> HOÀN THÀNH! Bạn có thể mở file 'benchmark_report.csv' và ảnh 'pqc_latency_chart.png' ra để dán vào bài Lab.")


if __name__ == "__main__":
    run_benchmark()