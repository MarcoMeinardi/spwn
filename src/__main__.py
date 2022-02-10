import sys
from spwn import Spwn

manual_selection = "manual" in sys.argv
search_ropgadgets = "rop" in sys.argv
Spwn(manual_selection, search_ropgadgets)