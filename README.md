# Reversing.kr Write-up 
## Easy Crack - 100pts

Nếu các bạn chưa có tools vui lòng xem qua [PicoCTF-2022 WU](https://github.com/lephuduc/PicoCTF-2022) để down tools về

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

## Easy Keygen - 100pts
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

## Easy Unpack - 100pts

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

## Easy ELF - 100pts

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

## Replace - 150pts

![image](https://user-images.githubusercontent.com/88520787/174284963-0859f88b-dafb-4d6a-b098-dbbdbcdcf444.png)

Bài này vẫn là check password (chỉ được nhập vào kí tự là số), tuy nhiên khi mở IDA tìm hàm check thì mình không thấy, debug thử thì khi bấm `Check` nó bị lỗi như này:

![image](https://user-images.githubusercontent.com/88520787/174285235-a266e0b8-f7fd-4793-bd35-51de2cf27808.png)

`40466F: Lệnh tại 0x40466F tham chiếu bộ nhớ tại 0x601605CB. Không thể ghi bộ nhớ -> 601605CB`

Thử nhập 1 số:

![image](https://user-images.githubusercontent.com/88520787/174285824-52cce0b2-f316-41e7-896f-c20f44e4d489.png)

Vẫn là lỗi lệnh ở vị trí `40466F`,mình tìm thử trong data:

![image](https://user-images.githubusercontent.com/88520787/174286024-9f1e4bab-6457-42cd-a779-c1a26409649c.png)

Tại đây chương trình thực hiện lệnh `call $+5` rất là lạ, mình đặt breakpoint và debug thử (input để trống):

![image](https://user-images.githubusercontent.com/88520787/174287105-d55df6d0-6ef2-4f31-a03d-b654b4f0c9dc.png)

Sau khi tắt debug, chạy lại với input = 4567, mình để ý `dword_4084D0` nó sẽ có giá trị thay đổi dựa theo input, cụ thể là input+2 và được cộng với `601605C7h`:

![image](https://user-images.githubusercontent.com/88520787/174287785-ea396c0c-5db8-469c-b9dd-2812ed211ac6.png)

Và nó được tăng thêm 2 lần trước khi được push và call (chổ `inc eax` và `inc dword_4084D0`)

Nghĩa là lỗi kia do không thể tìm thấy offset chính xác để call, ta cần tính toán cụ thể để ra được đúng địa chỉ, qua tab string, ta có:

![image](https://user-images.githubusercontent.com/88520787/174288099-8ca47fb5-3bd7-4138-b8b6-77c3e55e6bee.png)
![image](https://user-images.githubusercontent.com/88520787/174291594-50aa5fcd-cc30-4d07-8152-5bef9b53224d.png)

Địa chỉ chính xác của mình chính là `0x00401071`

Hộp thoại báo lỗi của chương trìn khi mình không nhập gì là `0x601605CB`, khi mình nhập `4567` thì sẽ là `0x601617A2` chính là `0x601605CB+ hex(4567)`

```
input + 2 + 0x601605C7 + 2 = 0x00401071
input = (0x00401071 - 2 - 2 - 0x601605C7) & 0xffffffff = 2687109798 // & với 0xffffffff chuyển thành số dương
```
![image](https://user-images.githubusercontent.com/88520787/174293047-7aec64c1-d211-4992-a3f0-a90fdcc6520d.png)

`input = 2687109798`

## ImagePrc - 120pts

Để xem đề cho cái gì đây

![image](https://user-images.githubusercontent.com/88520787/174296085-4d4c8a99-08e2-4aa9-a280-a26bcc7373c8.png)

![image](https://user-images.githubusercontent.com/88520787/174296333-fc740095-b230-41a6-81aa-13c0a268b970.png)

Một cái file có thể vẽ lên xong còn có nút `Check`, hmmm, mình đoán là nó sẽ so sánh hình mình vẽ với data có sẵn, vậy giờ kím data đó ở đâu?

Trước tiên mình thử tìm hàm `check`:
```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  int SystemMetrics; // eax
  HWND Window; // eax
  int v7; // [esp-1Ch] [ebp-64h]
  struct tagMSG Msg; // [esp+4h] [ebp-44h] BYREF
  WNDCLASSA WndClass; // [esp+20h] [ebp-28h] BYREF

  ::hInstance = hInstance;
  WndClass.cbClsExtra = 0;
  WndClass.cbWndExtra = 0;
  WndClass.hbrBackground = (HBRUSH)GetStockObject(0);
  WndClass.hCursor = LoadCursorA(0, (LPCSTR)0x7F00);
  WndClass.hInstance = hInstance;
  WndClass.hIcon = LoadIconA(0, (LPCSTR)0x7F00);
  WndClass.lpfnWndProc = sub_401130;
  WndClass.lpszClassName = lpWindowName;
  WndClass.lpszMenuName = 0;
  WndClass.style = 3;
  RegisterClassA(&WndClass);
  v7 = GetSystemMetrics(1) / 2 - 75;
  SystemMetrics = GetSystemMetrics(0);
  Window = CreateWindowExA(
             0,
             lpWindowName,
             lpWindowName,
             0xCA0000u,
             SystemMetrics / 2 - 100,
             v7,
             200,
             150,
             0,
             0,
             hInstance,
             0);
  ShowWindow(Window, 5);
  if ( !GetMessageA(&Msg, 0, 0, 0) )
    return Msg.wParam;
  do
  {
    TranslateMessage(&Msg);
    DispatchMessageA(&Msg);
  }
  while ( GetMessageA(&Msg, 0, 0, 0) );
  return Msg.wParam;
}
```
Trong Winmain có hàm `sub_401130` rất kì lạ, vào xem thử thì...

```c
case 1u:
          DC = GetDC(hWnd);
          hbm = CreateCompatibleBitmap(DC, 200, 150);
          hdc = CreateCompatibleDC(DC);
          h = SelectObject(hdc, hbm);
          Rectangle(hdc, -5, -5, 205, 205);
          ReleaseDC(hWnd, DC);
          ::wParam = (WPARAM)CreateFontA(12, 0, 0, 0, 400, 0, 0, 0, 0x81u, 0, 0, 0, 0x12u, pszFaceName);
          dword_4084E0 = (int)CreateWindowExA(
                                0,
                                ClassName,
                                WindowName,
                                0x50000000u,
                                60,
                                85,
                                80,
                                28,
                                hWnd,
                                (HMENU)0x64,
                                hInstance,
                                0);
          SendMessageA((HWND)dword_4084E0, 0x30u, ::wParam, 0);
          return 0;
```

Có chổ hàm `CreateCompatibleBitmap()` mình biết được kích thước tấm ảnh của mình và của chương trình là `200x150`

```c
if ( wParam == 100 )
    {
      GetObjectA(hbm, 24, pv);
      memset(&bmi, 0, 0x28u);
      bmi.bmiHeader.biHeight = cLines;
      bmi.bmiHeader.biWidth = v16;
      bmi.bmiHeader.biSize = 40;
      bmi.bmiHeader.biPlanes = 1;
      bmi.bmiHeader.biBitCount = 24;
      bmi.bmiHeader.biCompression = 0;
      GetDIBits(hdc, (HBITMAP)hbm, 0, cLines, 0, &bmi, 0);
      v8 = operator new(bmi.bmiHeader.biSizeImage);
      GetDIBits(hdc, (HBITMAP)hbm, 0, cLines, v8, &bmi, 0);
      ResourceA = FindResourceA(0, (LPCSTR)101, (LPCSTR)0x18);
      Resource = LoadResource(0, ResourceA);
      v11 = LockResource(Resource);
      v12 = 0;
      v13 = v8;
      v14 = v11 - (_BYTE *)v8;
      while ( *v13 == v13[v14] )
      {
        ++v12;
        ++v13;
        if ( v12 >= 90000 )
        {
          sub_401500(v8);
          return 0;
        }
      }
      MessageBoxA(hWnd, Text, Caption, 0x30u);
      sub_401500(v8);
      return 0;
    }
```
Còn đây sẽ là chổ so sánh từng `byte` với `bitmap` có sẵn, trước khi cmp thì hàm có dùng `GetDIBits,GetDIBits,FindResourceA,LoadResource`, xem như là lấy data lên trước khi so sánh, để xem được trong file có những vùng data nào thì mình dùng `ResourceHacker`:

![image](https://user-images.githubusercontent.com/88520787/174300806-ef89e720-03d9-4a43-9100-88fe75e9535e.png)

Rồi luôn, Nó đây, 0xFF đại diện cho màu trắng (màu sáng nhất) và ngược lại, giờ tì mình tìm cách để biến cái đống này thành bitmap có thể xem được

Để xem được ta cần có file header đúng chuẩn với header của bitmap, mình có thể lê mạng copy và thay vào hoặc là tạo 1 file bitmap bằng paint (nhớ điều chỉnh độ phân giải là 200x150 trước khi lưu):

![image](https://user-images.githubusercontent.com/88520787/174301231-8c2ccddb-dbbf-430c-be70-77b48823c380.png)

Sau khi lưu, mở file bằng Hxd (hoặc hex editor bất kì để chỉnh sửa hex):

![image](https://user-images.githubusercontent.com/88520787/174301746-4dd7b445-9bfa-46ac-88eb-93852c1df0de.png)

Copy data từ bên ResourceHacker qua và lưu lại thành tấm ảnh hoàn chỉnh.Mở lên thử hehe

![image](https://user-images.githubusercontent.com/88520787/174302263-5d2b5b3f-f0ca-4819-9e35-246fac069e84.png)

`Key: GOT`

## Music Player - 150pts

Không hiểu sao bài này lại là bài làm mình stuck nhiều nhất

![image](https://user-images.githubusercontent.com/88520787/174303891-7ae9cf75-2fbd-4ba6-bdc6-e51390173817.png)

Trong file ReadMe có nói rõ là bài này ta sẽ tìm hàm check và pass qua chổ đó:
```
This MP3 Player is limited to 1 minutes.
You have to play more than one minute.

There are exist several 1-minute-check-routine.
After bypassing every check routine, you will see the perfect flag.
```
Khi chạy tới 1 phút sẽ có 1 cái MsBox hiện cái gì đó lên như thế này:

![image](https://user-images.githubusercontent.com/88520787/174304052-73f1d28a-d5cf-4510-a404-7769f94ba959.png)

Vì hàm và tên hàm rất lộn xộn, mình lay hoay mãi mà không tìm đc chổ check, ban đầu mình tìm `Msbox` nhưng cũng không thấy

![image](https://user-images.githubusercontent.com/88520787/174304442-e1ac13c4-a76e-4180-8546-21f299a17a78.png)

Chợt nhớ ra trong bài này có kèm theo 1 file `.dll`, vậy nên mình kiểm tra xem chương trình đã import những gì để sử dụng những, check thử tab import:

![image](https://user-images.githubusercontent.com/88520787/174304807-6dd9d5e1-55e8-4536-a004-633c6c786fae.png)

Mãi đến giờ thì mình mới thấy cái `WinAPI` này:))), giờ bấm đúp vào với dùng `xref`( bấm X) xem coi những thằng nào gọi nó:

![image](https://user-images.githubusercontent.com/88520787/174305049-c5aa7d38-6579-4a47-baae-022714691a06.png)

Một đống luôn:))

Sau khi check và debug một hồi thì mình tìm được chổ cái `msbox 1??????` mà nó từng hiện lên là cái này:

![image](https://user-images.githubusercontent.com/88520787/174305318-02bd256f-496f-479f-a85c-ed1e454d86a9.png)

Mà để nhảy tới chổ này thì có câu điều kiện này:

![image](https://user-images.githubusercontent.com/88520787/174305681-74d408ed-128b-491b-8c8f-184152b0b6da.png)

Vì sau lệnh này, nó bắt buộc phải nhảy tới block khác, nếu không nó sẽ nhảy vào block chứa `Msbox fail`

Trước đó nó có chổ `cmp eax, 60000` và cũng có nghĩa là cmp với `60000ms = 1p`, nếu lớn hơn thì không jump và đi vào `FAIL`, ngược lại thì jump.

Để bypass lệnh mình dùng Plugin IDA do người Việt viết có tên là [keypatch](https://github.com/keystone-engine/keypatch), cho phép mình chỉnh sửa lệnh trực tiếp bằng tổ hợp phím `Ctrl + Alt + K`, mình đổi lệnh `jl` thành `jmp`:

![image](https://user-images.githubusercontent.com/88520787/174306841-517627bd-5e68-4ef3-89b0-87647030aeae.png)

![image](https://user-images.githubusercontent.com/88520787/174306980-f61985d8-01e6-45f4-a142-6197a1d2979d.png)

Lưu vào input file và chạy thử:

![image](https://user-images.githubusercontent.com/88520787/174307101-e3c98c61-a32c-49b1-af22-d3be6a19263a.png)

Vẫn còn lỗi ạ, stuck tiếp :<<<, mình nghĩ là vẫn còn thêm chổ check nữa,

Sau khi pass qua được chổ kia, mình lần theo `jmp` của nó thì thấy được thêm 1 chổ này:

![image](https://user-images.githubusercontent.com/88520787/174307455-d277f084-9169-45b2-baa0-d963063a25db.png)

```call    ds:__vbaHresultCheckObj```

Chắc chổ này phá cái bài của mình, làm tương tự như bước trên, mình pass qua cái check này bằng lệnh `jmp` luôn:

![image](https://user-images.githubusercontent.com/88520787/174307735-bf87074e-a1c9-4c2b-a032-9c40228af217.png)

![image](https://user-images.githubusercontent.com/88520787/174307803-6a4d44e2-15a3-4e72-806e-1665772b361d.png)

Chạy thử lần nữa:

![image](https://user-images.githubusercontent.com/88520787/174307945-d3a70636-e598-43d7-8a37-47f62d0d5980.png)

File lần này chạy mượt lắm nha, không có lỗi gi:)))

## CSHOP - 120pts

Bài này mình thấy khá dễ so với những bài ở trên, nhưng không hiểu sao lại ít người làm hơn

![image](https://user-images.githubusercontent.com/88520787/174309513-cc1827e2-c3ea-4fc4-8007-1b7f306de652.png)

Một cái file trắng tinh tươm.....

![image](https://user-images.githubusercontent.com/88520787/174308938-472716fa-e8e2-425f-a944-dd45f1d2dda2.png)

Bài này là dotNet nên mình đã dùng [dnSpy](https://github.com/dnSpy/dnSpy) để phân tích:

![image](https://user-images.githubusercontent.com/88520787/174309235-e47dd68d-a6b6-4e95-a887-40e96f0e0976.png)

Theo kinh nghiệm của mình code của bài này đã bị obfuscate, ban đầu mình nghĩ là sẽ unobfuscate trước sau đó phân tích sau, nhưng khi đọc sơ qua thì mình thấy có 1 chổ hơi bất ổn:

![image](https://user-images.githubusercontent.com/88520787/174309728-0d6f0712-3de7-40de-96f4-e0af47e046e2.png)

![image](https://user-images.githubusercontent.com/88520787/174309814-741aee6f-c3d9-44d4-be15-b06d2025274c.png)

Đây là một cái `button` nhưng mà sao lại set size bằng 0,0 thế kia, mình thử chỉnh size to hơn một tí:

![image](https://user-images.githubusercontent.com/88520787/174309976-49fdbfd7-5bb8-4c15-ba09-73976e0eb44a.png)

![image](https://user-images.githubusercontent.com/88520787/174310045-215cf9cc-cac7-4fc4-87c6-b7cbccfa2740.png)

Sửa thành 100,100 sau đó lưu file lại

![image](https://user-images.githubusercontent.com/88520787/174310141-a3bfc71c-a639-4982-9dd5-e47eb151c00c.png)

Chạy thử thấy cái nút to quá, bấm thử ra flag luôn:))

![image](https://user-images.githubusercontent.com/88520787/174310346-e3b0c96e-1bf0-42ba-a9d2-fd7cc203d950.png)

## Position - 160pts

![image](https://user-images.githubusercontent.com/88520787/174311267-1eeff0fa-5025-4aa8-835c-b2882bb46610.png)

![image](https://user-images.githubusercontent.com/88520787/174311676-f7fb9ba3-4280-486d-ba33-ca6083ec7b6a.png)

![image](https://user-images.githubusercontent.com/88520787/174311246-8735c204-32db-4831-9e58-7adc73f6fb58.png)

Tiếp tục là một bài keygen nữa

Lấy kinh nghiệm từ bài trước (Musicplayer), lần này mình check tab `import` và `string` trước và thứ mình cần tìm là chổ nào in ra `Wrong` hoặc là chổ nào sẽ nhận input của mình:

![image](https://user-images.githubusercontent.com/88520787/174312296-b820aed7-1615-4c31-b9c5-6c9de50095de.png)

Mình thấy có chổ `GetWinDowTextW`, xref tới xem những thằng nào gọi nó:

![image](https://user-images.githubusercontent.com/88520787/174312530-f994a579-ee71-48a2-a27c-9f0ad6c779a6.png)

![image](https://user-images.githubusercontent.com/88520787/174312705-c7a0556f-ea2a-4b3c-be7f-003806bfe4c7.png)

Có 2 chổ gọi và lưu vào biến `v50` và `v51`, trong đó `v50` có check điều kiện là `[a-z]` nên mình khá chắc đây là name, còn lại là serial, mình đã đổi tên lại cho dễ nhìn

![image](https://user-images.githubusercontent.com/88520787/174313331-9fa4dd20-f462-4ecc-aaa2-50d4abab0f98.png)

Đoạn này thật ra chỉ check xem name có kí tự nào trùng nhau hay không thôi

Rồi bây giờ mới bắt đầu check tên:

![image](https://user-images.githubusercontent.com/88520787/174313917-72bd5b06-eef4-4105-9c06-2e2a926023ee.png)

Mình ngẫm sơ qua 1 hồi thì, serial chỉ có thể có giá trị 6,7,8 vì điều kiện của kí tự đầu tiền luôn +5, kí tự tiếp theo +1


Mình đã copy và sửa tên thành tên khác dễ hiểu hơn:

```c
c1 = (name[0] & 1) + 5;
    c2 = ((name[0] & 0x10) != 0) + 5;
    c3 = ((name[0] & 2) != 0) + 5;
    c4 = ((name[0] & 4) != 0) + 5;
    c5 = ((name[0] & 8) != 0) + 5;
    c4_ = (name[1] & 1) + 1;
    c3_ = ((name[1] & 0x10) != 0) + 1;
    c2_ = ((name[1] & 2) != 0) + 1;
    c1_ = ((name[1] & 4) != 0) + 1;
    c5_ = ((name[1] & 8) != 0) + 1;
    check += ((c1 + c1_)== 7 );
    check += ((c5 + c5_)== 6 );
    check += ((c3 + c3_)== 8 );
    check += ((c4 + c4_)== 7 );
    check += ((c2 + c2_)== 6 );
```
![image](https://user-images.githubusercontent.com/88520787/174314842-98bb1ebb-eb98-4027-894e-5c413cbbb9c7.png)

Tương tự với kí tự thứ 3 và kí tự cuối cùng

```c
c6 = (name[2] & 1) + 5;
    c7 = ((name[2] & 0x10) != 0) + 5;
    c8 = ((name[2] & 2) != 0) + 5;
    c9 = ((name[2] & 4) != 0) + 5;
    c10 = ((name[2] & 8) != 0) + 5;
    c9_ = (name[3] & 1) + 1;
    c8_ = ((name[3] & 0x10) != 0) + 1;
    c7_ = ((name[3] & 2) != 0) + 1;
    c6_ = ((name[3] & 4) != 0) + 1;
    c10_ = ((name[3] & 8) != 0) + 1;
    check += ((c6 + c6_)== 7 );
    check += ((c10 + c10_)== 7 );
    check += ((c8 + c8_)== 7 );
    check += ((c9 + c9_)== 7 );
    check += ((c7 + c7_)== 6 );
```

Tổng hợp lại, mình có hàm check như sau:

```c
bool check(string name){
    int c1,c2,c3,c4,c5,c1_,c2_,c3_,c4_,c5_,c6,c7,c8,c9,c10,c6_,c7_,c8_,c9_,c10_;
    int check = 0;
    c1 = (name[0] & 1) + 5;
    c2 = ((name[0] & 0x10) != 0) + 5;
    c3 = ((name[0] & 2) != 0) + 5;
    c4 = ((name[0] & 4) != 0) + 5;
    c5 = ((name[0] & 8) != 0) + 5;
    c4_ = (name[1] & 1) + 1;
    c3_ = ((name[1] & 0x10) != 0) + 1;
    c2_ = ((name[1] & 2) != 0) + 1;
    c1_ = ((name[1] & 4) != 0) + 1;
    c5_ = ((name[1] & 8) != 0) + 1;
    // 5 so dau cua serial
    check += ((c1 + c1_)== 7 );
    check += ((c5 + c5_)== 6 );
    check += ((c3 + c3_)== 8 );
    check += ((c4 + c4_)== 7 );
    check += ((c2 + c2_)== 6 );
    c6 = (name[2] & 1) + 5;
    c7 = ((name[2] & 0x10) != 0) + 5;
    c8 = ((name[2] & 2) != 0) + 5;
    c9 = ((name[2] & 4) != 0) + 5;
    c10 = ((name[2] & 8) != 0) + 5;
    c9_ = (name[3] & 1) + 1;
    c8_ = ((name[3] & 0x10) != 0) + 1;
    c7_ = ((name[3] & 2) != 0) + 1;
    c6_ = ((name[3] & 4) != 0) + 1;
    c10_ = ((name[3] & 8) != 0) + 1;
    //5 so sau cua serial
    check += ((c6 + c6_)== 7 );
    check += ((c10 + c10_)== 7 );
    check += ((c8 + c8_)== 7 );
    check += ((c9 + c9_)== 7 );
    check += ((c7 + c7_)== 6 );
    return check ==10;
}
```
Giờ mình bruteforce 3 kí tự đầu của pass thôi, 26^3 chắc nhanh mà :>

```c
#include <bits/stdc++.h>
using namespace std;
bool check(string name){
    int c1,c2,c3,c4,c5,c1_,c2_,c3_,c4_,c5_,c6,c7,c8,c9,c10,c6_,c7_,c8_,c9_,c10_;
    int check = 0;
    c1 = (name[0] & 1) + 5;
    c2 = ((name[0] & 0x10) != 0) + 5;
    c3 = ((name[0] & 2) != 0) + 5;
    c4 = ((name[0] & 4) != 0) + 5;
    c5 = ((name[0] & 8) != 0) + 5;
    c4_ = (name[1] & 1) + 1;
    c3_ = ((name[1] & 0x10) != 0) + 1;
    c2_ = ((name[1] & 2) != 0) + 1;
    c1_ = ((name[1] & 4) != 0) + 1;
    c5_ = ((name[1] & 8) != 0) + 1;
    // 5 so dau cua serial
    check += ((c1 + c1_)== 7 );
    check += ((c5 + c5_)== 6 );
    check += ((c3 + c3_)== 8 );
    check += ((c4 + c4_)== 7 );
    check += ((c2 + c2_)== 6 );
    c6 = (name[2] & 1) + 5;
    c7 = ((name[2] & 0x10) != 0) + 5;
    c8 = ((name[2] & 2) != 0) + 5;
    c9 = ((name[2] & 4) != 0) + 5;
    c10 = ((name[2] & 8) != 0) + 5;
    c9_ = (name[3] & 1) + 1;
    c8_ = ((name[3] & 0x10) != 0) + 1;
    c7_ = ((name[3] & 2) != 0) + 1;
    c6_ = ((name[3] & 4) != 0) + 1;
    c10_ = ((name[3] & 8) != 0) + 1;
    //5 so sau cua serial
    check += ((c6 + c6_)== 7 );
    check += ((c10 + c10_)== 7 );
    check += ((c8 + c8_)== 7 );
    check += ((c9 + c9_)== 7 );
    check += ((c7 + c7_)== 6 );
    return check ==10;
}
void brutePass(string name,int length,string set){
    if (name.size()==length) return;
    for (auto c:set){
        string temp = name+ c;
        if (check(temp) && temp[3]=='p'){
            cout<<temp<<endl;
            break;
        }
        brutePass(temp,length,set);
    }
}
int main(){
    string set = "abcdefghijklmnopqrstuvwxyz";
    brutePass("",4,set);
    return 0;
}
```
Có 4 kết quả:

![image](https://user-images.githubusercontent.com/88520787/174315558-22bce8ad-8c70-40e8-b1fd-26bc692c50c2.png)

Thấy cái đầu hợp lí nhất nên thử luôn:

![image](https://user-images.githubusercontent.com/88520787/174315709-986c6481-344f-4928-96f0-5c19d7e505c2.png)

# Direct3D FPS - 140pts

![image](https://user-images.githubusercontent.com/88520787/174316869-66684374-34f7-42e3-ba7c-fb0d35fe14ed.png)

Adu tự nhiên có game fps chơi:)))

Nhiệm vụ của mình là đi clear mấy con này, bắn nào hết thì có pass:>

![image](https://user-images.githubusercontent.com/88520787/174319167-dd1c2e52-b490-47e0-8e8f-bd7dcaa57c37.png)

Bắn xong mình cũng k thấy cái gì luôn:))

Chơi zui xíu thôi, vào phân tích nào, thử tìm trong string mình có thấy cái này:

![image](https://user-images.githubusercontent.com/88520787/174319773-34d278e0-58cb-40fa-9234-337583d4cd93.png)

Mình trace ra thì thấy hàm `sub_4039C0` có gọi tới chổ này:
```c
int *sub_4039C0()
{
  int *result; // eax

  result = &dword_409194;
  while ( *result != 1 )
  {
    result += 132;
    if ( (int)result >= (int)&unk_40F8B4 )
    {
      MessageBoxA(hWnd, aCkfkbulileEZf, "Game Clear!", 0x40u);
      return (int *)SendMessageA(hWnd, 2u, 0, 0);
    }
  }
  return result;
}
```
Trong lúc xuất ra thông báo `Game Clear` thì cũng có kèm theo đoạn chuỗi này, nhưng nhìn có vẻ không ổn lắm:

![image](https://user-images.githubusercontent.com/88520787/174320168-673747cd-88d4-48e6-bca9-b081674e6ecf.png)

Mình thử xref thì thấy nó còn được đem đi xor, khác chắc là decryt

![image](https://user-images.githubusercontent.com/88520787/174320281-1b4e1a97-8c4d-474a-b6f4-72b11c5fa066.png)

```c
int __thiscall sub_403400(void *this)
{
  int result; // eax
  int v2; // edx

  result = sub_403440(this);
  if ( result != -1 )
  {
    v2 = dword_409190[132 * result];
    if ( v2 > 0 )
    {
      dword_409190[132 * result] = v2 - 2;
    }
    else
    {
      dword_409194[132 * result] = 0;
      data[result] ^= byte_409184[528 * result];
    }
  }
  return result;
}
```
Mình đã đổi tên biến thành data cho dễ nhìn, nó được lấy từng kí tự đem đi xor với các `byte_409184`, xem thử chổ `byte_409184+528 này có gì`

![image](https://user-images.githubusercontent.com/88520787/174320674-1c5cb6c2-a6ca-4ef9-828e-0a754777b418.png)

Mình thử dùng python có sẵn trong IDA thì được kết quả như này: (0x002D9184 là vị trí của byte_409184)
```
  Python>b = 0x002D9184 
  Python>get_bytes(b,1)
  b'\x00'
  Python>get_bytes(b+518,1)
  b'S'
  Python>b = 0x002D9184
  Python>get_bytes(b,1)
  b'\x00'
  Python>get_bytes(b+528,1)
  b'\x04'
  Python>get_bytes(b+528*2,1)
  b'\x08'
```
Mình dự đoán được rằng byte_409184 sẽ là một mảng từ 0,4,8,12,16...rồi dùng đem xor với data có sẵn mà chúng ta đã thấy

Minh viết scipt này để lấy data và `byte_409184` ra sau đó đem xor với nhau:

```py
data = 0x0407028 #data start address
j =0
for i in range(50):
    print(chr(int.from_bytes(get_bytes(data+i,1),"big")^j),end = "")
    j+=4
```
Dùng chức năng load script file của IDA để chạy file py:

![image](https://user-images.githubusercontent.com/88520787/174325081-31fabc3b-ad36-4374-b29f-18593f2703a8.png)

Kết quả là:

![image](https://user-images.githubusercontent.com/88520787/174325163-7001307a-5fdd-4bf6-91cc-1c634a58b7f9.png)

## Multiplicative - 170pts

Lần này ta sẽ rev file jar

Mình dùng `jadx` để `decompile` ra:

 ![image](https://user-images.githubusercontent.com/88520787/174328214-7d8ca6bf-1492-4587-a903-aa4af26c9855.png)

Nhìn sơ qua thì source code khá đơn giản chỉ là nhận vào rồi kiểm tra, tuy nhiên nó không dễ như bình thường

Mình đã thử

![image](https://user-images.githubusercontent.com/88520787/174329285-a99e3944-9583-4a24-b989-9b235cef3d27.png)

Bài này dùng phép nhân trước khi tính toán, nên mình chăc chắn đây là overflow luôn

Kiểu `long` có 64 bit cho nên số lớn nhất sẽ là 2^63-1, sau khi lớn hơn giá trị này nó sẽ quay về -2^63, vậy nên ta sẽ tính toán giá trị hợp lí cho nó quay về 
-1536092243306511225

Chuyển -1536092243306511225 sang số không dấu ta được 0xeaaeb43e477b8487

Theo như tính chất của overflow, thì (0xeaaeb43e477b8487 + 2^64.n) sẽ là bội số của 26729, vậy nên mình có script như sau:

```py
from ctypes import *
i = 0
while True:
    if ((2**64)*i + 0xeaaeb43e477b8487)%26729==0:
        print((2**64)*i + 0xeaaeb43e477b8487)
        break
    i+=1
print(c_int64(253087792599051741660295//26729))
```
Kết quả là
`-8978084842198767761`

## ransomware - 120pts

Còn về phần bài này, đề cho 1 `file` và 1 file `run.exe`, và file readme có nói rõ:

![image](https://user-images.githubusercontent.com/88520787/174447216-4d87a54f-863f-4d9b-b7f9-77099a1acd51.png)

Vì đề bài là ransomware(1 loại virus phá hoại) mình biết là bằng cách nào đó, cái file này đã làm mã hóa `file` khiến cho nó không thể hoạt động được:

![image](https://user-images.githubusercontent.com/88520787/174447530-ef62a808-b867-4c99-a0c7-ad5149f3f6fa.png)

Còn đây là file exe, sau khi nhập key bừa thì mình phát hiện `file` đã bị thay đổi nội dung:

![image](https://user-images.githubusercontent.com/88520787/174447602-5fa9e63d-4181-4859-86b3-7caf78d774b2.png)

![image](https://user-images.githubusercontent.com/88520787/174447627-d60eaf5f-6774-4826-bf4f-88ae58261d15.png)

Giờ nhiệm vụ của mình là tìm đúng key để giải mã cái đống này thôi:>

![image](https://user-images.githubusercontent.com/88520787/174447651-630560f8-614d-4aa6-ae35-c79fe8a34242.png)

File `run.exe` là file đã packed, mình dùng extentions có sẵn của `CFF Explorer` để unpack nó:

![image](https://user-images.githubusercontent.com/88520787/174447704-b0b0ac42-53c6-4dc7-82a4-affa201969fb.png)

Lưu thành file mới và đưa vào `IDA` xem thử nào:

![image](https://user-images.githubusercontent.com/88520787/174447752-11eb765c-0576-4cb6-99aa-b1bba54c0720.png)

![image](https://user-images.githubusercontent.com/88520787/174447778-46b1592a-0931-43e1-bfc7-44d648560ebf.png)


Đây là hàm main, phía trên còn có khúc `pusha` `popa` rất nhiều, tạm thời ta không cần quan tâm

Để ý các bạn có thể thấy, chương trình có đoạn dùng fopen mở file có tên là `file`, mode là `rb`, nghĩa là đọc bytes từ file mà đề cho

![image](https://user-images.githubusercontent.com/88520787/174448790-aec21cbb-adff-466a-85d6-0d882ba384f2.png)

Trong suốt chương trình thì ta luôn thấy nó gọi tới hàm `sub_401000`, nhưng mà nội dung của nó cũng k có gì đặc biệt, ta bỏ qua tiếp

![image](https://user-images.githubusercontent.com/88520787/174447923-3a15e1b4-1dd6-48bb-9514-7744ef932ced.png)

Quay trở lại vấn đề chính, sau khi gọi lệnh đọc file, thì đoạn này chương trình sẽ có vòng lặp lấy từng byte của file sau đó lưu vào `byte_5415B8`:

![image](https://user-images.githubusercontent.com/88520787/174448009-d749410e-e452-4334-b8e9-2ca08427243c.png)

Sau khi đọc hết file, chương trình nhảy tới đoạn `loc_44A8A5`

![image](https://user-images.githubusercontent.com/88520787/174448050-509e7a1b-a31f-44aa-a283-a3d0aa89c43b.png)

Qua quá trình debug thì mình mới biết `[ebp+var_8]` sẽ là biến đếm từ 0 tới `[ebp+var_10]`(độ dài của `file`), nếu nhỏ hơn thì tiếp tục vòng lặp, tạm gọi là `i` và `n`.

![image](https://user-images.githubusercontent.com/88520787/174448177-2e49835c-02d2-445a-86a4-824c7cf3bd55.png)

Đoạn này có 3 lệnh `xor`, tuy nhiên khúc `xor` đầu tiên chỉ là để clear thanh ghi `edx`, ngoài ra còn có đoạn dùng `div` cho `[ebp+var_C]` (độ dài của key từ người dùng), `div` sẽ lấy `eax` chia cho thanh ghi toán hạng nguồn, sau đó lưu số dư vào `edx`.

```
movsx   edx, byte_44D370[edx]
```
byte_44D370 chính là key của người dùng nhập vào,

Sau đó các file bytes của chúng ta còn được `xor` với 0xFF, tổng kết lại, mình đọc được đoạn nó encrypt như sau:
```c
byte[i] = byte[i]^key[i%len(key)]^0xFF
```
Trong đó `key` và `len(key)` đều không biết được, nên là mình đã nghĩ tởi bruteforce key, nhưng không được :V

Mình đã thử lấy file gốc `xor` với `0xFF` trước:

```py
b = bytearray(open('file', 'rb').read())
for i in range(len(b)):
    b[i] = b[i]^0xFF
open('file_new', 'wb').write(b)
```

Mở `file_new` bằng HxD, mình thấy có vài thứ hay ho:

![image](https://user-images.githubusercontent.com/88520787/174448552-079ad4c5-c1b5-4de8-b668-deb408ce8a0c.png)

Mình thấy có 1 đoạn text có thể đọc được và lặp đi lặp lại rất nhiều lần, chắc chắn đây là key luôn, thử nhập vào file `run.exe`:

![image](https://user-images.githubusercontent.com/88520787/174448601-8b61888f-c259-4ff9-885f-58bd2c36bcf4.png)

Mở `file` lên thử:

![image](https://user-images.githubusercontent.com/88520787/174448620-81ba3592-4357-46a4-8ca1-a2518cbb9189.png)

Có vẻ như là key đúng rồi, nhưng mà sao để chạy file này đây?

![image](https://user-images.githubusercontent.com/88520787/174448677-4d6b4643-4528-4580-9cea-49a663f4393f.png)

Dùng DiE thì mình thấy đây là file thực thi 32bits và packed, unpack và đưa vào ida xem thử:v

![image](https://user-images.githubusercontent.com/88520787/174448711-8607cf41-db47-4620-93df-55f43ab56ae2.png)

Có luôn:)) `Colle System`

# HateIntel - 150pts

Nghe tên bài và icons là mình biết bài này dùng cái gì luôn:

![image](https://user-images.githubusercontent.com/88520787/174478661-2a12a2f0-f12b-46fb-b52e-96aed1e73d33.png)

![image](https://user-images.githubusercontent.com/88520787/174478675-9f6b842e-9192-4eca-9cb4-0342b58e8e7f.png)

File đề cho là file thực thi trên `macOS`, tuy nhiên file dùng compiler là `gcc` nên code vẫn là code C như thông thường, IDA hoàn toàn có thể hỗ trợ decompile:

![image](https://user-images.githubusercontent.com/88520787/174478751-6224cad1-5aff-4784-8dc6-4ab630209174.png)

`macOS` sẽ dùng kiến trúc `ARM (arm architecture)` thay vì `intel_x86,_x64` mà mấy bài trước chúng ta rev, tập lệnh của `ARM` có đặc điểm nhận diện là thường viết HOA hết các lệnh, nhưng mà đây chỉ là kiến thức thêm, trong phạm vi bài này, ta chỉ đọc code C thuần nên không quan tâm lắm, còn đây là hàm `main()`:

```c
int sub_2224()
{
  char __s[80]; // [sp+4h] [bp-5Ch] BYREF
  int v2; // [sp+54h] [bp-Ch]
  int v3; // [sp+58h] [bp-8h]
  int i; // [sp+5Ch] [bp-4h]

  v2 = 4;
  printf("Input key : ");
  scanf("%s", __s);
  v3 = strlen(__s);
  sub_232C(__s, v2);
  for ( i = 0; i < v3; ++i )
  {
    if ( __s[i] != byte_3004[i] )
    {
      puts("Wrong Key! ");
      return 0;
    }
  }
  puts("Correct Key! ");
  return 0;
}
```

Chương trình lấy chuỗi của người dùng nhập vào, sau đó đưa vào hàm `sub_232C` (tạm gọi là hàm encrypt) xử lí, sau đó so sánh với các `byte` có sẵn trong data chương trình:

![image](https://user-images.githubusercontent.com/88520787/174479003-3116bc2e-db87-41c5-9aac-8a741b3dee49.png)

Vào trong hàm `encrypt` xem thử:

```c
signed __int32 __fastcall encrypt(signed __int32 result, int a2)
{
  char *__s; // [sp+4h] [bp-10h]
  int i; // [sp+8h] [bp-Ch]
  signed __int32 j; // [sp+Ch] [bp-8h]

  __s = (char *)result;
  for ( i = 0; i < a2; ++i )
  {
    for ( j = 0; ; ++j )
    {
      result = strlen(__s);
      if ( result <= j )
        break;
      __s[j] = sub_2494((unsigned __int8)__s[j], 1);
    }
  }
  return result;
}
```

Hàm này duyệt qua chuỗi 4 lần (a2 = 4), mỗi lần từng kí tự sẽ được thay đổi bởi hàm `sub_2494`:

```c
int __fastcall sub_2494(unsigned __int8 a1, int a2)
{
  int v3; // [sp+8h] [bp-8h]
  int i; // [sp+Ch] [bp-4h]

  v3 = a1;
  for ( i = 0; i < a2; ++i )
  {
    v3 *= 2;
    if ( (v3 & 0x100) != 0 )
      v3 |= 1u;
  }
  return (unsigned __int8)v3;
}
```

Hàm `sub_2494` cũng có 1 vòng lặp, nhưng a2 = 1, nên ta xem như không có vòng lặp, ta chỉ quan tâm logic của hàm, mình thấy có đoạn `v3 |= 1u;` nên mình nghĩ hàm này sẽ xử lí thao tác bit:

Code của hàm sẽ trông dễ hiểu hơn:

```c
int rotate(char c){
    c <<=1;
    if ( (c & 0x100) != 0 ) c |= 1u;
    return (unsigned __int8)c; // lấy 8 bits cuối
}
```
Cả đoạn này hiểu như sau: dịch 8 bits của kí tự sang trái, lấy bit đầu tiên thêm vào cuối, hay nói cách khác là `rotate bits`, khi rotate 4 lần thì 4 bits đầu thành 4 bits cuối và ngược lại, với data `bytes` có sẵn, mình có script để rev như sau:

```py
b = [0x44, 0xF6, 0xF5, 0x57, 0xF5, 0xC6, 0x96, 0xB6, 0x56,0xF5, 0x14, 0x25, 0xD4, 0xF5, 0x96, 0xE6, 0x37, 0x47,0x27, 0x57, 0x36, 0x47, 0x96, 3, 0xE6, 0xF3, 0xA3,0x92]
for byte in b:
    last = byte>>4
    first = byte&0xF
    s = (first<<4) | last 
    print(chr(s),end = "") #Do_u_like_ARM_instructi0n?:)
```
Result: `Do_u_like_ARM_instructi0n?:)`


