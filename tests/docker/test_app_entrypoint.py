import os
import subprocess
import sys
from pathlib import Path


ENTRYPOINT = Path(__file__).parents[2] / "docker" / "app-entrypoint.sh"


def run_entrypoint(tmp_path: Path, config_values: dict[str, str]):
    config_dir = tmp_path / ".enclava" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / ".ready").write_text("ready_at=1\n")
    for key, value in config_values.items():
        (config_dir / key).write_text(value)

    seed_path = tmp_path / "seed"
    seed_path.write_text("test-seed")

    env = {
        "APP_SEED_PATH": str(seed_path),
        "MINT_DATABASE": str(tmp_path / "mint"),
        "MINT_AUTH_DATABASE": str(tmp_path / "mint"),
        "NUTSHELL_CAP_CONFIG_DIRS": str(config_dir),
        "NUTSHELL_CAP_CONFIG_WAIT_SECONDS": "0",
        "NUTSHELL_REQUIRED_SPARK_STORAGE_DIR": str(tmp_path / "spark"),
        "PATH": os.environ["PATH"],
        "TMPDIR": str(tmp_path / "tmp"),
    }
    cmd = [
        str(ENTRYPOINT),
        sys.executable,
        "-c",
        "import os; print(os.environ.get('MINT_BACKEND_BOLT11_SAT')); "
        "print(os.environ.get('MINT_SPARK_STORAGE_DIR')); "
        "print(os.path.isdir(os.environ.get('MINT_SPARK_STORAGE_DIR', '')))",
    ]
    return subprocess.run(cmd, env=env, text=True, capture_output=True)


def test_entrypoint_loads_cap_config_for_spark(tmp_path: Path):
    result = run_entrypoint(
        tmp_path,
        {
            "MINT_BACKEND_BOLT11_SAT": "SparkWallet",
            "MINT_SPARK_API_KEY": "test-api-key",
            "MINT_SPARK_MNEMONIC": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "MINT_SPARK_STORAGE_DIR": str(tmp_path / "spark"),
        },
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["SparkWallet", str(tmp_path / "spark"), "True"]


def test_entrypoint_rejects_incomplete_spark_config(tmp_path: Path):
    result = run_entrypoint(
        tmp_path,
        {
            "MINT_BACKEND_BOLT11_SAT": "SparkWallet",
            "MINT_SPARK_API_KEY": "test-api-key",
            "MINT_SPARK_STORAGE_DIR": str(tmp_path / "spark"),
        },
    )

    assert result.returncode != 0
    assert "MINT_SPARK_MNEMONIC is required" in result.stderr


def test_entrypoint_rejects_wrong_enclava_spark_storage_dir(tmp_path: Path):
    result = run_entrypoint(
        tmp_path,
        {
            "MINT_BACKEND_BOLT11_SAT": "SparkWallet",
            "MINT_SPARK_API_KEY": "test-api-key",
            "MINT_SPARK_MNEMONIC": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "MINT_SPARK_STORAGE_DIR": "data/spark",
        },
    )

    assert result.returncode != 0
    assert f"MINT_SPARK_STORAGE_DIR must be {tmp_path / 'spark'}" in result.stderr
