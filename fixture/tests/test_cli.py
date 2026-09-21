from fixture_app import __version__, greeting, main


def test_greeting():
    assert greeting("ci") == "hello, ci"


def test_main_prints_the_greeting(capsys):
    assert main(["ci"]) == 0
    assert capsys.readouterr().out == "hello, ci\n"


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as exit_:
        assert exit_.code == 0
    assert __version__ in capsys.readouterr().out
