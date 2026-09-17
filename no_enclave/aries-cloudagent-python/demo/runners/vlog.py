#our own violet-output helper so every line we print shares one colour
#upstream support/utils.py is left untouched; this only wraps the same raw print()
#the white timing lines already use, adding a violet ANSI colour around the text

#violet (#8A2BE2) as a 24-bit ANSI foreground; change here to retune the shade
VIOLET = "\033[38;2;138;43;226m"
#reset back to the terminal default after each line
RESET = "\033[0m"
#same colour for prompt_toolkit log_msg calls so both match
VIOLET_STYLE = "fg:#8a2be2"


def vprint(*args, **kwargs) -> None:
    #drop-in for print(): join the args like print does, wrap them in violet, flush
    text = " ".join(str(a) for a in args)
    #default to flush=True like our timing prints, but let a caller override it
    kwargs.setdefault("flush", True)
    print(f"{VIOLET}{text}{RESET}", **kwargs)


def vstatus(*args, **kwargs) -> None:
    #drop-in for the demo's log_status(): a violet banner with a leading blank line
    text = " ".join(str(a) for a in args)
    vprint(f"\n{text}", **kwargs)
