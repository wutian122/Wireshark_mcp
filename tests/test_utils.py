import pytest
import asyncio
from unittest.mock import patch, MagicMock
from utils.subproc import run_tshark, run_tshark_async
import subprocess

def test_run_tshark_success():
    """测试同步执行成功"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="success",
            stderr=""
        )
        code, out, err = run_tshark(["echo", "test"])
        assert code == 0
        assert out == "success"

def test_run_tshark_timeout():
    """测试同步执行超时"""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="sleep", timeout=1)

        with pytest.raises(subprocess.TimeoutExpired):
            run_tshark(["sleep", "5"], timeout=1)

@pytest.mark.asyncio
async def test_run_tshark_async_success():
    """测试异步执行成功"""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"async_out", b"")
        mock_proc.returncode = 0

        # 使 mock_exec 返回一个 awaitable 对象
        future = asyncio.Future()
        future.set_result(mock_proc)
        mock_exec.return_value = future

        code, out, err = await run_tshark_async(["echo", "async"])
        assert code == 0
        assert out == "async_out"
