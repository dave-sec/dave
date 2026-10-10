import os

# Les tests ne doivent jamais interroger GitHub (test_updates utilise un faux serveur).
os.environ.setdefault("DAVE_NO_UPDATE_CHECK", "1")
