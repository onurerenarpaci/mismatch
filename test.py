import ram

source = {
    "size": 10,
    "code": [
        {
            "OpCode": 1,
            "args": [5, 2]
        },
        {
            "OpCode": 7,
            "args": []
        }
    ]
}

ram1 = ram.Ram(source)
ram1()