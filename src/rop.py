import os
import re

class ROP:
    def __init__(self, file_name, output_file, gadgets_prefix = ""):
        self.file_name = file_name
        self.output_file = output_file
        self.gadgets_prefix = gadgets_prefix
        self.save_all_gadgets()

    def save_all_gadgets(self):
        '''
        Extract rop gadgets from binary file with ROPgadget
        '''
        os.system(f"ROPgadget --binary {self.file_name} --multibr > {self.output_file}")

    def extract_basic_gadgets(self, gadgets_to_search):
        '''
        Takes a list of regex or list of regex as input and return a string with the python code to set the gadgets with decent naming and address
        If a element of the list is a single regex, every match will be saved
        If a element of the list is a list of regex, only the first occurrence of the first matched regex will be saved
        '''
        with open(self.output_file, "r") as f:
            ropgadgets = f.read()
        script_gadgets = ""
        for gadget_element in gadgets_to_search:
            # Single regex (match every occurrence)
            if isinstance(gadget_element, str):
                gadget_regex = gadget_element
                actual_gadget = self.search_gadgets(ropgadgets, gadget_regex, False)
                if actual_gadget is not None:
                    script_gadgets += actual_gadget

            # List of regex (match only the first occurrence of the "first to be found" regex)
            elif isinstance(gadget_element, list):
                for gadget_regex in gadget_element:
                    actual_gadget = self.search_gadgets(ropgadgets, gadget_regex, True)
                    if actual_gadget is not None:
                        script_gadgets += actual_gadget
                        break

        return script_gadgets

    def search_gadgets(self, full_gadgets, gadget_regex, only_first):
        '''
        Search rop gadget in full_gadgets based on gadget_regex
        If only_first is True, it will return only the first occurrence, otherwise it will recursively search every occurrence
        '''
        if gadget_match := re.search(gadget_regex, full_gadgets):
            gadget = gadget_match.group()
            address, gadget_name = gadget.split(":")
            gadget_name = gadget_name[1:-1].upper()
            gadget_name = re.sub(r"( ; |, | )", "_", gadget_name)
            address = address[:-1]
            script_gadget = f"{self.gadgets_prefix}{gadget_name} = {address}\n"
            if only_first:
                return script_gadget
            else:
                next_occurrences = self.search_gadgets(full_gadgets[gadget_match.span()[1]:], gadget_regex, False)
                if next_occurrences is not None:
                    return script_gadget + next_occurrences
                else:
                    return script_gadget
        else:
            return None