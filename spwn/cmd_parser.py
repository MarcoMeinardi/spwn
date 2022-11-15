import argparse

def inflate_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		prog = "spwn",
		description = "spwn is a tool to quickly start a pwn challenge, for more informations check https://github.com/MarcoMeinardi/spwn",
		epilog = "Bug report: https://github.com/MarcoMeinardi/spwn/issues",
	)

	parser.add_argument(
		"-i", "--inter",
		action = "store_true",
		help = "Interactively create interaction functions",
	)

	parser.add_argument(
		"-io", "--ionly",
		action = "store_true",
		help = "Create the interaction functions, without doing any analysis",
	)

	subparsers = parser.add_subparsers(dest="subparsers_called", prog="prog", help="sub-command help")

	config_parser = subparsers.add_parser(
		"config",
		help = "Edit configuration options",
	)

	config_parser.add_argument(
		"--get",
		nargs="+",
		help = "Get the value of a configuration option",
	)

	config_parser.add_argument(
		"--set",
		nargs="+",
		help = "Set the value of a configuration option",
	)

	config_parser.add_argument(
		"--reset",
		nargs="+",
		help = "Reset the value of a configuration option to the default",
	)

	config_parser.add_argument(
		"--list",
		action = "store_true",
		help = "List all configuration options",
	)

	return parser
