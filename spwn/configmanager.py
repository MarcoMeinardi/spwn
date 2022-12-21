import json
import os
from typing import Any


class ConfigManager:
	def __init__(self, config_path: str) -> None:
		config_path = os.path.expanduser(config_path)
		configs = json.load(open(config_path))
		for conf in configs:
			if isinstance(configs[conf], str) and configs[conf].startswith("~/"):
				configs[conf] = os.path.expanduser(configs[conf])

		configs["config_path"] = config_path
		super().__setattr__("configs", configs)

	def __getattribute__(self, key: str) -> None:
		configs = super(ConfigManager, self).__getattribute__("configs")
		if key in configs:
			return configs[key]
		else:
			raise KeyError

	def __setattr__(self, key: str, value: Any) -> None:
		configs = super(ConfigManager, self).__getattribute__("configs")
		if key in configs:
			configs[key] = value
		else:
			raise KeyError
