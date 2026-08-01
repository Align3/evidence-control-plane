"""Keep the fixture corpus out of the real collection.

`fixtures/` contains `test_*.py` files that exist to be *read* by the matrix
generator, not executed. They import nothing real and assert nothing useful;
collecting them would put fictional 900-block requirement IDs into the live
node-id list and corrupt the matrix the generator produces for this repo.
"""

collect_ignore_glob = ["fixtures/*"]
