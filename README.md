nonce
=====

simple php based nonce generation classes (composable, abstracted repository)

The actual class code is defined between the comment blocks "code under test".  Everything else is extraneous.

I did poor man's testing rather than learn PHPUnit... sorry...

If you wanted to do in-memory cache based nonce handling, you could easily implement a different repository.

If you were in a web farm scenario, you could implement a database based repository.

The last few tests show how the classes might be composed together and used in an actual application.

Enjoy
