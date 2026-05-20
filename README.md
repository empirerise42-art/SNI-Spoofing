# SNI Proxy — TCP Scanner & DPI Bypass

ابزار دور زدن DPI/سانسور با جعل SNI در هندشیک TLS.

## نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

> **نکته:** ماژول `pydivert` و درایور WinDivert فقط روی Windows کار می‌کنند.  
> بدون آن‌ها ابزار در حالت relay ساده اجرا می‌شود (بدون DPI bypass کامل).

## اجرا

```bash
python main.py
```

## راهنمای سریع

1. روی **🔍 اسکن دامنه‌ها** کلیک کنید تا لیست `sni_list.txt` اسکن شود.  
2. روی یک ردیف با کیفیت خوب کلیک کنید تا به‌طور خودکار انتخاب شود.  
3. روی **▶️ راه‌اندازی پروکسی** کلیک کنید.  
4. پروکسی خود را روی `127.0.0.1:40443` (یا پورت تنظیم‌شده) قرار دهید.

## فایل‌های مهم

| فایل | توضیح |
|------|-------|
| `sni_list.txt` | لیست دامنه‌های SNI برای اسکن (یک دامنه در هر خط) |
| `config.json` | تنظیمات پروکسی |
| `debug.log` | لاگ کامل اجرا |

## حمایت از پروژه

USDT (BEP20): `0x76a768B53Ca77B43086946315f0BDF21156bF424`  
USDT (TRC20): `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`

https://t.me/projectXhttp  
https://t.me/patterniha
