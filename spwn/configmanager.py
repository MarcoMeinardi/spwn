import json
import os

class ConfigManager:
	def __init__(self, config_path) -> None:
		self.config_path = os.path.expanduser(config_path)
		self.configs = json.load(open(self.config_path))
		for conf in self.configs:
			if isinstance(self.configs[conf], str) and self.configs[conf].startswith("~/"):
				self.configs[conf] = os.path.expanduser(self.configs[conf])

	def __getitem__(self, key):
		if key in self.configs:
			return self.configs[key]
		else:
			raise KeyError("No such config")
