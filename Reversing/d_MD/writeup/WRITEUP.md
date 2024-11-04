### Exploit
```c
    int __fastcall main(int argc, const char **argv, const char **envp)
    {
    __int64 v3; // rax
    __int64 v4; // rax
    __int64 v5; // rax
    __int64 v6; // rax
    __int64 v7; // rax
    __int64 v8; // rax
    __int64 v9; // rax
    __int64 v10; // rax
    __int64 v11; // rax
    __int64 v12; // rax
    __int64 v13; // rax
    __int64 v14; // rax
    __int64 v15; // rax
    __int64 v16; // rax
    __int64 v17; // rax
    __int64 v18; // rax
    __int64 v19; // rax
    __int64 v20; // rax
    __int64 v21; // rax
    __int64 v23; // rax
    __int64 v24; // rax
    __int64 v25; // rax
    __int64 v26; // rax
    __int64 v27; // rax
    __int64 v28; // rax
    __int64 v29; // rax
    __int64 v30; // rax
    __int64 v31; // rax
    __int64 v32; // rax
    __int64 v33; // rax
    __int64 v34; // rax
    __int64 v35; // rax
    __int64 v36; // rax
    __int64 v37; // rax
    char v38; // [rsp+Fh] [rbp-71h] BYREF
    _BYTE v39[16]; // [rsp+10h] [rbp-70h] BYREF
    _BYTE v40[8]; // [rsp+20h] [rbp-60h] BYREF
    __int64 v41; // [rsp+28h] [rbp-58h]
    _BYTE v42[56]; // [rsp+30h] [rbp-50h] BYREF
    unsigned __int64 v43; // [rsp+68h] [rbp-18h]

    v43 = __readfsqword(0x28u);
    std::operator<<<std::char_traits<char>>(&std::cout, "Enter the valid key!\n", envp);
    std::operator>><char,std::char_traits<char>>(&edata, v42);
    std::allocator<char>::allocator(&v38);
    std::string::string(v39, v42, &v38);
    md5(v40, v39);
    v41 = std::string::c_str((std::string *)v40);
    std::string::~string((std::string *)v40);
    std::string::~string((std::string *)v39);
    std::allocator<char>::~allocator(&v38);
    if ( *(_WORD *)v41 == '87'
        && *(_BYTE *)(v41 + 2) == '0'
        && *(_BYTE *)(v41 + 3) == '4'
        && *(_BYTE *)(v41 + 4) == '3'
        && *(_BYTE *)(v41 + 5) == '8'
        && *(_BYTE *)(v41 + 6) == 'd'
        && *(_BYTE *)(v41 + 7) == '5'
        && *(_BYTE *)(v41 + 8) == 'b'
        && *(_BYTE *)(v41 + 9) == '6'
        && *(_BYTE *)(v41 + 10) == 'e'
        && *(_BYTE *)(v41 + 11) == '2'
        && *(_BYTE *)(v41 + 12) == '9'
        && *(_BYTE *)(v41 + 13) == 'd'
        && *(_BYTE *)(v41 + 14) == 'b'
        && *(_BYTE *)(v41 + 15) == '0'
        && *(_BYTE *)(v41 + 16) == '8'
        && *(_BYTE *)(v41 + 17) == '9'
        && *(_BYTE *)(v41 + 18) == '8'
        && *(_BYTE *)(v41 + 19) == 'b'
        && *(_BYTE *)(v41 + 20) == 'c'
        && *(_BYTE *)(v41 + 21) == '4'
        && *(_BYTE *)(v41 + 22) == 'f'
        && *(_BYTE *)(v41 + 23) == '0'
        && *(_BYTE *)(v41 + 24) == '2'
        && *(_BYTE *)(v41 + 25) == '2'
        && *(_BYTE *)(v41 + 26) == '5'
        && *(_BYTE *)(v41 + 27) == '9'
        && *(_BYTE *)(v41 + 28) == '3'
        && *(_BYTE *)(v41 + 29) == '5'
        && *(_BYTE *)(v41 + 30) == 'c'
        && *(_BYTE *)(v41 + 31) == '0' )
    {
        v3 = std::operator<<<std::char_traits<char>>(&std::cout, 84LL);
        v4 = std::operator<<<std::char_traits<char>>(v3, 104LL);
        v5 = std::operator<<<std::char_traits<char>>(v4, 101LL);
        v6 = std::operator<<<std::char_traits<char>>(v5, 32LL);
        v7 = std::operator<<<std::char_traits<char>>(v6, 107LL);
        v8 = std::operator<<<std::char_traits<char>>(v7, 101LL);
        v9 = std::operator<<<std::char_traits<char>>(v8, 121LL);
        v10 = std::operator<<<std::char_traits<char>>(v9, 32LL);
        v11 = std::operator<<<std::char_traits<char>>(v10, 105LL);
        v12 = std::operator<<<std::char_traits<char>>(v11, 115LL);
        v13 = std::operator<<<std::char_traits<char>>(v12, 32LL);
        v14 = std::operator<<<std::char_traits<char>>(v13, 118LL);
        v15 = std::operator<<<std::char_traits<char>>(v14, 97LL);
        v16 = std::operator<<<std::char_traits<char>>(v15, 108LL);
        v17 = std::operator<<<std::char_traits<char>>(v16, 105LL);
        v18 = std::operator<<<std::char_traits<char>>(v17, 100LL);
        v19 = std::operator<<<std::char_traits<char>>(v18, 32LL);
        v20 = std::operator<<<std::char_traits<char>>(v19, 58LL);
        v21 = std::operator<<<std::char_traits<char>>(v20, 41LL);
        std::ostream::operator<<(v21, &std::endl<char,std::char_traits<char>>);
        return 0;
    }
    else
    {
        v23 = std::operator<<<std::char_traits<char>>(&std::cout, 73LL);
        v24 = std::operator<<<std::char_traits<char>>(v23, 110LL);
        v25 = std::operator<<<std::char_traits<char>>(v24, 118LL);
        v26 = std::operator<<<std::char_traits<char>>(v25, 97LL);
        v27 = std::operator<<<std::char_traits<char>>(v26, 108LL);
        v28 = std::operator<<<std::char_traits<char>>(v27, 105LL);
        v29 = std::operator<<<std::char_traits<char>>(v28, 100LL);
        v30 = std::operator<<<std::char_traits<char>>(v29, 32LL);
        v31 = std::operator<<<std::char_traits<char>>(v30, 75LL);
        v32 = std::operator<<<std::char_traits<char>>(v31, 101LL);
        v33 = std::operator<<<std::char_traits<char>>(v32, 121LL);
        v34 = std::operator<<<std::char_traits<char>>(v33, 33LL);
        v35 = std::operator<<<std::char_traits<char>>(v34, 32LL);
        v36 = std::operator<<<std::char_traits<char>>(v35, 58LL);
        v37 = std::operator<<<std::char_traits<char>>(v36, 40LL);
        std::ostream::operator<<(v37, &std::endl<char,std::char_traits<char>>);
        return 0;
    }
    }
```

IDA로 디컴파일해보면 해당 코드를 확인할 수 있다. C++로 짜여진 코드인 것 같고, 사용자가 key 값을 입력하면 해당 값을 md5 해싱하여 `780438d5b6e29db0898bc4f0225935c0` 와 같은지 비교한다.

주의할 점은 처음에 word로 할당된 87은 리틀엔디언을 고려하여 78로 생각해야 한다. md5 디코딩 사이트에 해당 해시 값을 넣어보면 `b781cbb29054db12f88f08c6e161c199` 이 출력된다. 즉, `b781cbb29054db12f88f08c6e161c199` 을 md5 해싱하면 `780438d5b6e29db0898bc4f0225935c0` 이 나오기 때문에 올바른 키를 넣은 것으로 간주된다.