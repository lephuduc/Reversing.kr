# Reversing.kr Write-up 
## Easy Crack

Nếu các bạn chưa có tools vui lòng xem qua [Write-up PicoCTF2022]() để down tools về

Mở file lên thì ta biết đây là 1 file check password

![image](https://user-images.githubusercontent.com/88520787/174267344-c4849fc3-4968-4beb-b854-f8a939883420.png)

Kiểm tra bằng [DiE](https://github.com/horsicq/Detect-It-Easy) , ta thấy đây là 1 file PE32

![image](https://user-images.githubusercontent.com/88520787/174267750-13d8b36f-e684-4307-a51d-e60ef66a7832.png)

Mờ file bằng IDA 32bit, tại hàm `DialogFunc` có hàm `sub_401080`, nhìn sơ qua ta thấy hàm có sử dụng winapi `GetDlgItemTextA` và `MessageBoxA`, tức lấy thông tin từ ô nhập lưu vào biến `String`, kiểm tra và xuất thông báo

```c
int __cdecl sub_401080(HWND hDlg)
{
  CHAR String[97]; // [esp+4h] [ebp-64h] BYREF
  __int16 v3; // [esp+65h] [ebp-3h]
  char v4; // [esp+67h] [ebp-1h]

  memset(String, 0, sizeof(String));
  v3 = 0;
  v4 = 0;
  GetDlgItemTextA(hDlg, 1000, String, 100);
  if ( String[1] != 97 || strncmp(&String[2], Str2, 2u) || strcmp(&String[4], aR3versing) || String[0] != 69 )
    return MessageBoxA(hDlg, aIncorrectPassw, Caption, 0x10u);
  MessageBoxA(hDlg, Text, Caption, 0x40u);
  return EndDialog(hDlg, 0);
}
```
Dựa theo bảng ASCII và thứ tự các kí tự, ta truy xuất được pass như sau : `Ea5yR3versing`

![image](https://user-images.githubusercontent.com/88520787/174269389-2692b964-ab7c-4e44-83b6-5acaaab9d4fd.png)

## Easy Keygen
Đề cho ta 1 file `Readme.txt` và 1 file `Easy Keygen.exe`

![image](https://user-images.githubusercontent.com/88520787/174270121-3b063329-603a-4710-a519-53300fc89bdb.png)

![image](https://user-images.githubusercontent.com/88520787/174269902-0d478ba7-963f-4af8-af16-e544c73d370e.png)


Trong bài này ta cần phải tìm hiểu cách mà chương trình tạo ra `serial` từ chính `name` mà người dùng nhập vào, đó cũng là bản chất của `keygen (Key generator)`

File `Easy Keygen.exe` là file PE32, thử mở bằng IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v3; // ebp
  int i; // esi
  char v6; // [esp+Ch] [ebp-130h]
  char v7[2]; // [esp+Dh] [ebp-12Fh] BYREF
  char Var[100]; // [esp+10h] [ebp-12Ch] BYREF
  char Buffer[197]; // [esp+74h] [ebp-C8h] BYREF
  __int16 v10; // [esp+139h] [ebp-3h]
  char v11; // [esp+13Bh] [ebp-1h]

  memset(Var, 0, sizeof(Var));
  memset(Buffer, 0, sizeof(Buffer));
  v10 = 0;
  v11 = 0;
  v6 = 16;
  qmemcpy(v7, " 0", sizeof(v7));
  print(aInputName);
  scanf("%s", Var);
  v3 = 0;
  for ( i = 0; v3 < (int)strlen(Var); ++i )
  {
    if ( i >= 3 )
      i = 0;
    sprintf(Buffer, "%s%02X", Buffer, Var[v3++] ^ v7[i - 1]);
  }
  memset(Var, 0, sizeof(Var));
  print(aInputSerial);
  scanf("%s", Var);
  if ( !strcmp(Var, Buffer) )
    print(aCorrect);
  else
    print(aWrong);
  return 0;
}
```
Đọc kĩ thì mình thấy sau khi chương trình nhận `name` từ người dùng sau đó chương trình lấy từng kí tự của name `xor` với lại mảng `v7` đã được tạo từ trước

```c
sprintf(Buffer, "%s%02X", Buffer, Var[v3++] ^ v7[i - 1]);
```

Còn đây là cách khởi tạo của mảng `v7` dưới dạng code asm:

![image](https://user-images.githubusercontent.com/88520787/174272756-9d7d37eb-0201-4060-ac88-ea0e027e35f3.png)

`v7 = [0x10,0x20,0x30]`

Vì `xor` có tính chất đối xứng, từ đó mình có thể viết ra được script solve như sau:

```py
serial = "5B134977135E7D13"
b = bytes.fromhex(serial)
v7 = [0x10,0x20,0x30]
for i in range(8):
    print(chr(int(b[i])^v7[i%3]),end ="") #K3yg3nm3
```
`Name: K3yg3nm3` 

## Easy Unpack

Trong Reverse Engineering có 1 kĩ thuật tên là Unpack, nghĩa là file bị pack sẽ khiến ta không thể còn đọc code như bình thường nữa:

![image](https://user-images.githubusercontent.com/88520787/174274976-8481253c-5a4c-4c77-af62-672d9fb02798.png)

![image](https://user-images.githubusercontent.com/88520787/174275841-4c2c28d8-472b-43be-8737-d39ccf00afd7.png)

> Trong chương trình bình thường sẽ có 1 `EP(Entry Point)` gọi là điểm khởi đầu xuất phát của chương trình, tại điểm này trở đi, code sẽ được thực thi, trường hợp file bị pack, **EP** này có thể bị thay đổi.
 
> Tùy the packer, chương trình sau khi bị pack sẽ có 1 vùng data, **EP** này sẽ bắt đầu thực hiện giải mã data thành code chương trình gốc. Sau khi giải mã xong nó mới bắt đầu thực hiện chương trình bằng **EP** gốc hay còn gọi là `OEP(Original-Entry-Point)`.

Do đó, một trong những bước đầu tiên để unpack file đó chính là tìm ra **OEP** của chương trình, trong chall lần này đề chỉ yêu cầu tìm ra **OEP**:

![image](https://user-images.githubusercontent.com/88520787/174277363-6e5e4c56-a816-42b6-aedb-9b3a18ded6cc.png)

Dùng PE-Editor, mình tìm được EP hiện tại:

![image](https://user-images.githubusercontent.com/88520787/174277781-5da3c00b-5cf5-4ffd-92fa-1fb41a101d03.png)

Mình tìm bằng cách dự đoán, nghĩa là code sau khi dược decrypt thì sẽ nhảy đến **OEP** để thực thi chương trình, tìm kĩ trong IDA ta thấy:


![image](https://user-images.githubusercontent.com/88520787/174279804-5a2ba587-e404-4e20-a869-0c7a838dab08.png)

![image](https://user-images.githubusercontent.com/88520787/174280264-892ed865-7ab4-480f-898f-76e4b44db5da.png)

Tại khúc này mình thấy nó `jmp` thẳng từ dưới lên location 0x401150, mình dự đoán luôn, đây chính là **OEP**

![image](https://user-images.githubusercontent.com/88520787/174280105-5ef978c6-5efe-4dad-8c4f-24d33c9034ca.png)

`OEP:00401150`

##Easy ELF

Tương tự với file `exe` trên Windows, `ELF` sẽ là file thực thi trên hệ điều hành Linux

![image](https://user-images.githubusercontent.com/88520787/174281001-b3721602-d421-40b2-a4ea-a8881d498781.png)

Vì là file ELF nên mới vào ta mở và kiếm ngay hàm `main` để decompile:

```c
int __cdecl main()
{
  write(1, "Reversing.Kr Easy ELF\n\n", 0x17u);
  sub_8048434();
  if ( sub_8048451() == 1 )
    sub_80484F7();
  else
    write(1, "Wrong\n", 6u);
  return 0;
}
```

Bên trong `sub_8048434` thật ra chỉ là hàm nhập bình thường (bài này sẽ là nhập vào 1 chuỗi) , mình đã đổi tên biến lại cho dễ quan sát:

```c
int sub_8048434()
{
  return __isoc99_scanf(&unk_8048650, &input);
}
```
Tại câu điều kiện `if` có 1 hàm dùng để kiểm tra `input` của người dùng:

```c
_BOOL4 CHECK()
{
  if ( byte_804A021 != 49 )
    return 0;
  input ^= 0x34u;
  byte_804A022 ^= 0x32u;
  byte_804A023 ^= 0x88u;
  if ( byte_804A024 != 88 )
    return 0;
  if ( byte_804A025 )
    return 0;
  if ( byte_804A022 != 124 )
    return 0;
  if ( input == 120 )
    return byte_804A023 == -35;
  return 0;
}
```
Mình thấy có mấy `byte` lạ lạ nên bấm vào xem thử, và mình thấy đây cũng chỉ là các kí tự tiếp theo của input vì nó nằm liên tiếp nhau:

![image](https://user-images.githubusercontent.com/88520787/174282581-4f434802-96f9-403e-a11c-65893ff00160.png)

Mình đổi tên các biến lại, và giờ code đã dễ đọc hơn rất nhiều:

```c
_BOOL4 CHECK()
{
  if ( input1 != 49 )
    return 0;
  input ^= 0x34u;
  input2 ^= 0x32u;
  input3 ^= 0x88u;
  if ( input4 != 88 )
    return 0;
  if ( input5 )
    return 0;
  if ( input2 != 124 )
    return 0;
  if ( input == 120 )
    return input3 == -35;
  return 0;
}
```

Mình rev lại đoạn này xong viết script py để giải nó đơn giản như sau (Hoặc các bạn cũng có thể giải tay, nhớ chuyển -35 thành số dương):
```py
input = [0]*5
input[0] = 120^0x34
input[1] = 49
input[2] = 124^0x32
input[3] = (0xdd)^0x88
input[4] = 88
print("".join([chr(c) for c in input]))
```
Password: `L1NUX`
