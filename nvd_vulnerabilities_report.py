#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
nvd_installed_apps_report.py

Скрипт виконує такі завдання:
1) Автоматично обирає 5 встановлених програм на комп'ютері
2) Шукає для них відомі вразливості (CVE) у базі NVD (NIST)
3) Відфільтровує вразливості з CVSS Base Score >= 8.0
4) Записує результат у CSV-файл для подальшого аналізу
"""

from __future__ import annotations

import csv
import json
import os
import platform
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

# URL API бази вразливостей NVD (версія 2.0)
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ім'я вихідного CSV-файлу
OUTPUT_CSV = "nvd_vulnerabilities_report.csv"

# Скільки програм обрати для перевірки
PICK_COUNT = 5

# Мінімальний CVSS base score (High / Critical)
CVSS_MIN_SCORE = 8.0

# Максимальна кількість CVE з NVD на одну програму
RESULTS_PER_PAGE = 200

# Ліміт записів у CSV на одну програму
MAX_CVES_PER_PRODUCT_IN_CSV = 50

# Затримка між запитами до API (щоб не перевищити ліміти)
REQUEST_DELAY_SECONDS = 1.2


# ------------------------
# Модель програми
# ------------------------
@dataclass
class Program:
    """
    Представляє встановлену програму
    """
    name: str
    version: str = ""


def normalize_name(name: str) -> str:
    """
    Нормалізує назву програми (прибирає зайві пробіли)
    """
    name = re.sub(r"\s+", " ", name).strip()
    return name


def is_noise_program(name: str) -> bool:
    """
    Відсіює "шумові" записи:
    оновлення, runtime, redistributable, драйвери тощо
    """
    n = name.lower()
    noise_phrases = [
        "update", "hotfix", "security update", "kb",
        "redistributable", "runtime", "driver",
        "sdk", "framework", "language pack", "service pack"
    ]
    return any(p in n for p in noise_phrases)


# ------------------------
# Отримання встановлених програм
# ------------------------

def get_installed_programs_windows() -> List[Program]:
    """
    Отримує список встановлених програм у Windows з реєстру
    (без сторонніх бібліотек)
    """
    reg_paths = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    programs: List[Program] = []

    for path in reg_paths:
        cmd = ["reg", "query", path, "/s"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            continue

        display_name = None
        display_version = ""

        for line in proc.stdout.splitlines():
            if line.startswith("HKEY_"):
                if display_name:
                    programs.append(
                        Program(normalize_name(display_name), display_version)
                    )
                display_name = None
                display_version = ""
                continue

            m = re.match(r"^\s+(\S+)\s+REG_\S+\s+(.*)$", line)
            if not m:
                continue

            key, val = m.group(1), m.group(2)

            if key == "DisplayName":
                display_name = val
            elif key == "DisplayVersion":
                display_version = val

        if display_name:
            programs.append(Program(normalize_name(display_name), display_version))

    # Прибираємо дублікати
    unique = {(p.name, p.version): p for p in programs if p.name}
    return list(unique.values())


def get_installed_programs_linux() -> List[Program]:
    """
    Отримує встановлені пакети в Linux (Debian / Ubuntu) через dpkg
    """
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
            capture_output=True, text=True
        )
        programs = []
        for line in proc.stdout.splitlines():
            name, version = line.split("\t", 1)
            programs.append(Program(normalize_name(name), version))
        return programs
    except FileNotFoundError:
        return []


def get_installed_programs_macos() -> List[Program]:
    """
    Отримує список встановлених програм у macOS
    (може працювати повільно)
    """
    try:
        proc = subprocess.run(
            ["system_profiler", "SPApplicationsDataType", "-json"],
            capture_output=True, text=True
        )
        data = json.loads(proc.stdout)
        programs = []
        for app in data.get("SPApplicationsDataType", []):
            name = app.get("_name", "")
            version = app.get("version", "")
            if name:
                programs.append(Program(normalize_name(name), version))
        return programs
    except Exception:
        return []


def pick_5_programs(programs: List[Program]) -> List[Program]:
    """
    Обирає перші 5 "чистих" програм зі списку
    """
    filtered = [p for p in programs if p.name and not is_noise_program(p.name)]
    filtered.sort(key=lambda p: p.name.lower())
    return filtered[:PICK_COUNT]


# ------------------------
# Робота з NVD (CVE)
# ------------------------

def extract_best_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
    """
    Дістає найактуальніший CVSS score:
    пріоритет: CVSS v3.1 → v3.0 → v2
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            item = metrics[key][0]
            cvss = item.get("cvssData", {})
            return (
                cvss.get("baseScore"),
                cvss.get("vectorString", ""),
                item.get("baseSeverity", "")
            )
    return None, "", ""


# ------------------------
# Основна логіка
# ------------------------

def main() -> int:
    """
    Головна функція виконання скрипта
    """
    api_key = os.getenv("NVD_API_KEY", "")

    system = platform.system().lower()

    if "windows" in system:
        programs = get_installed_programs_windows()
    elif "linux" in system:
        programs = get_installed_programs_linux()
    elif "darwin" in system:
        programs = get_installed_programs_macos()
    else:
        print("Невідома операційна система")
        return 1

    selected_programs = pick_5_programs(programs)

    print("Обрані програми:")
    for p in selected_programs:
        print(f" - {p.name} {p.version}")

    rows = []

    for program in selected_programs:
        print(f"\nПошук вразливостей для: {program.name}")

        params = {
            "keywordSearch": f"\"{program.name}\"",
            "resultsPerPage": RESULTS_PER_PAGE,
        }

        headers = {"apiKey": api_key} if api_key else {}
        response = requests.get(NVD_CVE_API_URL, params=params, headers=headers)
        data = response.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            score, vector, severity = extract_best_cvss(cve.get("metrics", {}))

            if score is None or score < CVSS_MIN_SCORE:
                continue

            rows.append({
                "Program": program.name,
                "Version": program.version,
                "CVE": cve.get("id"),
                "CVSS": score,
                "Severity": severity,
                "Vector": vector,
                "Published": cve.get("published"),
                "Description": cve.get("descriptions", [{}])[0].get("value", "")
            })

        time.sleep(REQUEST_DELAY_SECONDS)

    # Запис у CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys() if rows else []
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nЗвіт збережено у файлі: {OUTPUT_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
