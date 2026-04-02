"""
Scanner Engine — Module chính của Member 1.

Đọc file parser_output (crossplane AST) → chạy tất cả Detectors đã đăng ký
→ tổng hợp kết quả → ghi ra file scan_result.json theo JSON Contract.

Usage (CLI):
    python -m core.scannerEng.scanner \
        --ssh-port 2221

Usage (Import):
    from core.scannerEng.scanner import Scanner
    scanner = Scanner(ssh_port=2221)
    result  = scanner.run("contracts/parser_output_2221.json", "contracts/scan_result_2221.json")
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Type

from core.scannerEng.base_recom import BaseRecom
from core.scannerEng.recommendations.detector_241 import Detector241
from core.scannerEng.recommendations.detector_242 import Detector242
from core.scannerEng.recommendations.detector_251 import Detector251
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID


# ---------------------------------------------------------------------------
# Detector Registry: tất cả Detector class, mapped bằng RecomID (Enum)
# ---------------------------------------------------------------------------

DETECTOR_REGISTRY: Dict[RecomID, Type[BaseRecom]] = {
    RecomID.CIS_2_4_1: Detector241,
    RecomID.CIS_2_4_2: Detector242,
    RecomID.CIS_2_5_1: Detector251,
}


class Scanner:
    """
    Orchestrator chạy tất cả các Detector trên cây AST của crossplane
    và tổng hợp kết quả ra đúng JSON Contract (scan_result.json).
    """

    def __init__(
        self,
        server_ip: str = "0.0.0.0",
        ssh_port: int = 22,
        ssh_user: str = "root",
        ssh_pass: str | None = None,
        ssh_key: str | None = None,
    ):
        self.server_ip = server_ip
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.ssh_key = ssh_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, input_path: str, output_path: str | None = None) -> Dict[str, Any]:
        """
        Pipeline chính:
            1. Đọc parser_output JSON (crossplane AST).
            2. Chạy từng Detector.scan() trên toàn bộ AST.
            3. Tổng hợp kết quả + tính compliance score.
            4. Ghi file output nếu output_path được cung cấp.
            5. Return dict kết quả.
        """
        parser_output = self._load_json(input_path)
        recommendations = self._run_all_detectors(parser_output)
        score = self._calculate_score(recommendations)

        scan_result = self._build_result(
            score=score,
            recommendations=recommendations,
        )

        if output_path:
            self._save_json(scan_result, output_path)

        return scan_result

    # ------------------------------------------------------------------
    # Internal: chạy tất cả Detectors
    # ------------------------------------------------------------------
    def _run_all_detectors(
        self, parser_output: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Với mỗi Detector đã đăng ký trong DETECTOR_REGISTRY:
            1. Khởi tạo instance.
            2. Gọi .scan(parser_output) → trả về list uncompliances.
            3. Nếu có uncompliance → thêm recommendation entry vào kết quả.
            4. Nếu không có uncompliance → vẫn thêm entry với status "pass".
        """
        results: List[Dict[str, Any]] = []

        for recom_id, detector_cls in DETECTOR_REGISTRY.items():
            detector = detector_cls()
            uncompliances = detector.scan(parser_output)

            # Lấy metadata từ registry chung
            recom_meta = RECOMMENDATION_REGISTRY.get(recom_id)

            entry: Dict[str, Any] = {
                "id": recom_id.value,
                "title": recom_meta.title if recom_meta else detector.title,
                "description": (
                    recom_meta.description if recom_meta else detector.description
                ),
                "rationale": recom_meta.rationale if recom_meta else "",
                "impact": recom_meta.impact if recom_meta else detector.impact,
            }

            if uncompliances:
                entry["status"] = "fail"
                entry["uncompliances"] = uncompliances
            else:
                entry["status"] = "pass"
                entry["uncompliances"] = []

            results.append(entry)

        return results

    # ------------------------------------------------------------------
    # Internal: tính điểm Compliance Score
    # ------------------------------------------------------------------
    @staticmethod
    def _calculate_score(recommendations: List[Dict[str, Any]]) -> int:
        """
        Compliance Score = (số luật PASS / tổng số luật) × 100

        Công thức đơn giản, trực quan cho Thesis Benchmark.
        Trả về số nguyên 0–100.
        """
        total = len(recommendations)
        if total == 0:
            return 100

        passed = sum(1 for r in recommendations if r.get("status") == "pass")
        return round((passed / total) * 100)

    # ------------------------------------------------------------------
    # Internal: xây dựng object kết quả cuối cùng
    # ------------------------------------------------------------------
    def _build_result(
        self,
        score: int,
        recommendations: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Tạo object JSON kết quả cuối cùng theo đúng JSON Contract.
        """
        return {
            "scan_id": 1,
            "server_ip": self.server_ip,
            "compliance_score": score,
            "created_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_json(filepath: str) -> Dict[str, Any]:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {filepath}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _save_json(data: Dict[str, Any], filepath: str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[Scanner] ✅ Scan result saved to: {path}")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SecRemedy Scanner Engine — CIS Benchmark Assessment",
    )
    parser.add_argument(
        "--input", "-i",
        help="Path to crossplane parser output JSON file (defaults to contracts/parser_output_<port>.json).",
    )
    parser.add_argument(
        "--output", "-o",
        help="Path to write the scan result JSON file (defaults to contracts/scan_result_<port>.json).",
    )
    parser.add_argument(
        "--server-ip",
        default="0.0.0.0",
        help="IP address of the target Nginx server (metadata only).",
    )
    parser.add_argument(
        "--ssh-port", "--port",
        type=int,
        default=22,
        help="SSH port of the target server.",
    )
    parser.add_argument(
        "--ssh-user", "--user",
        default="root",
        help="SSH username for the target server.",
    )
    parser.add_argument(
        "--ssh-pass",
        default=None,
        help="SSH password (optional).",
    )
    parser.add_argument(
        "--ssh-key",
        default=None,
        help="Path to SSH private key (optional).",
    )

    args = parser.parse_args()

    input_path = args.input or f"contracts/parser_output_{args.ssh_port}.json"
    output_path = args.output or f"contracts/scan_result_{args.ssh_port}.json"

    scanner = Scanner(
        server_ip=args.server_ip,
        ssh_port=args.ssh_port,
        ssh_user=args.ssh_user,
        ssh_pass=args.ssh_pass,
        ssh_key=args.ssh_key,
    )
    result = scanner.run(
        input_path=input_path,
        output_path=output_path,
    )

    total = len(result["recommendations"])
    passed = sum(1 for r in result["recommendations"]
                 if r.get("status") == "pass")
    failed = total - passed

    print(f"[Scanner] 📊 Compliance Score: {result['compliance_score']}%")
    print(f"[Scanner] 📋 Total: {total} | ✅ Pass: {passed} | ❌ Fail: {failed}")


if __name__ == "__main__":
    main()
