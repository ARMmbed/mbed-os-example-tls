# mbed TLS threading example on mbed OS

This application tests the thread safety of mbed TLS within mbed OS. The computations are performed sequentially at first to generate a reference value. Thereafter the aplication performs the same computations in parallel to test thread safety.

## Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

## Monitoring the application

The output in the terminal window should be similar to this:

```
Thread 0: Starting threads one by one...
Thread 1:  Done.
Thread 2:  Done.
Thread 0: Printing hash output...
Thread 0: 2794387f922b5f36953b6e02e6f499b7e1dbd19accb199192e8fd3c98c5fae7eb4f31f3c996c4ab28689eb5f137a4b947fc56a79698ca8c6ea1d3efec678a82c
Thread 0: Starting threads...
Thread 3:  Done.
Thread 4:  Done.
Thread 0: Printing hash output...
Thread 0: 2794387f922b5f36953b6e02e6f499b7e1dbd19accb199192e8fd3c98c5fae7eb4f31f3c996c4ab28689eb5f137a4b947fc56a79698ca8c6ea1d3efec678a82c
Thread 0: Done.
```

If the second hash string doesn't match the first, then the thread safety measures are not working properly and this build of mbed TLS is not thread safe!
