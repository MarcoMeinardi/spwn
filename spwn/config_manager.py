import json
import os

class ConfigManager:
    def __init__(self, config_path) -> None:
        try:
            self.config_path = os.path.expanduser(config_path)
            self.configs = json.load(open(self.config_path))
        except FileNotFoundError:
            self.configs = {}

        self.default_configs = json.load(open(os.path.expanduser("~/.config/spwn/.default_config.json")))

    def __getitem__(self, key):
        if key in self.configs:
            value = self.configs[key]
        elif key in self.default_configs:
            value = self.default_configs[key]
        else:
            value = None

        if value and "~" in value:
            value = os.path.expanduser(value)

        return value

    def __setitem__(self, key, value):
        self.configs[key] = value
        json.dump(self.configs, open(self.config_path, "w"), indent='\t')

    def keys(self):
        return self.configs.keys()

    def reset(self, key):
        if key in self.default_configs:
            self.configs[key] = self.default_configs[key]
        else:
            del self.configs[key]

        json.dump(self.configs, open(self.config_path, "w"), indent='\t')
