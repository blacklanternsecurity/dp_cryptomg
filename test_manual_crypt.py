from dp_manual_crypt import *


def test_config_parameter():
    param = ConfigParameter(b"foo,False,3,True")
    assert param.key == "foo"
    assert bool(param.value) == True
    assert param.param_type == 3

    param = ConfigParameter(b"foo,False,0,YmFy")
    assert param.value_raw == b"bar"
    assert param.encoded == True


def test_decrypt():
    parser = init_parser()
    args = parser.parse_args(
        ["-k", "DEADBEEF", "-d", "Hih4Mg4AHy4mDQ8oDgEANR0oBz0Ndw8uISw5AxsSPTweFjY%2BDgMXPyASFHk%3D"]
    )

    params = decrypt_params(args.decrypt, args.key.encode())
    assert "foo" in params.keys()
    assert str(params["foo"]) == "foo,False,1,bar"


def test_set():
    parser = init_parser()
    args = parser.parse_args(
        [
            "-k",
            "DEADBEEF",
            "-d",
            "Hih4Mg4AHy4mDQ8oDgEANR0oBz0Ndw8uISw5AxsSPTweFjY%2BDgMXPyASFHk%3D",
            "-s",
            "foo,False,3,True",
        ]
    )
    params = decrypt_params(args.decrypt, args.key.encode())
    new_params = set_params(params, [ConfigParameter(p.encode()) for p in args.set])
    assert new_params["foo"].param_type == 3
    assert bool(new_params["foo"].value) == True


def test_encrypt():
    parser = init_parser()
    args = parser.parse_args(["-k", "DEADBEEF", "-e", "foo,False,3,True"])
    params = {}
    for p in args.encrypt.split(";"):
        param = ConfigParameter(p.encode())
        params[param.key] = param
    encrypted = encrypt_params(params, args.key.encode())
    assert encrypted == "40Hih4Mg4AHy4mDQ8oDgEINRINC3UYFHh7"


def test_xor():
    xor = repeated_key_xor(b"Zm9vLEZhbHNlLDMsVHJ1ZQ==", b"DEADBEEF")
    assert xor == b"\x1e(x2\x0e\x00\x1f.&\r\x0f(\x0e\x01\x085\x12\r\x0bu\x18\x14x{"
