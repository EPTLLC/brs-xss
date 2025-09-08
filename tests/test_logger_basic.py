from brsxss.utils.logger import Logger


def test_logger_setup_and_success_level(tmp_path):
    log = Logger("tests.logger", level="DEBUG")
    # Add file handler
    fp = tmp_path / "app.log"
    log.add_file_handler(str(fp), level="INFO")
    assert fp.parent.exists()
    # Emit messages, including custom level
    log.debug("dbg")
    log.info("info")
    log.success("ok")
    log.error("err")
    # Change level
    log.set_level("WARNING")
