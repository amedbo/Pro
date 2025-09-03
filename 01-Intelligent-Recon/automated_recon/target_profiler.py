import nmap
import argparse
import sys

def target_profiler(target):
    """
    Profiles a target by scanning for open ports, services, and OS.
    """
    if not target:
        print("[-] لم يتم تحديد الهدف. الخروج.")
        return

    print(f"[+] بدء الفحص على الهدف: {target}")
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("[-] خطأ: لم يتم العثور على nmap. يرجى تثبيته على نظامك.")
        sys.exit(1)


    try:
        # -F: فحص سريع (أشهر 100 منفذ)
        # -sV: تحديد الخدمة/الإصدار
        # -O: الكشف عن نظام التشغيل
        print("[+] يتم إجراء الفحص الآن. قد يستغرق هذا بعض الوقت...")
        nm.scan(target, arguments='-F -sV -O')

        for host in nm.all_hosts():
            print("-" * 40)
            print(f"المضيف: {host} ({nm[host].hostname()})")
            print(f"الحالة: {nm[host].state()}")

            # نتائج الكشف عن نظام التشغيل
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                print("\n[+] نظام التشغيل المحتمل:")
                for osmatch in nm[host]['osmatch']:
                    print(f"  - {osmatch['name']} (الدقة: {osmatch['accuracy']}%)")
            else:
                print("\n[-] تعذر الكشف عن نظام التشغيل (قد يتطلب صلاحيات root).")

            # نتائج البروتوكولات (tcp, udp, etc.)
            print("\n[+] المنافذ المفتوحة:")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = nm[host][proto][port]
                    service = port_info.get('product', 'غير معروف')
                    version = port_info.get('version', '')
                    state = port_info['state']
                    print(f"  - المنفذ {port}/{proto}  \tالحالة: {state}  \tالخدمة: {service} {version}")

        print("-" * 40)

    except nmap.PortScannerError as e:
        print(f"[-] خطأ في فحص Nmap: {e}")
        print("[-] قد يكون هذا بسبب عدم تثبيت nmap على النظام.")
    except Exception as e:
        print(f"[-] حدث خطأ غير متوقع: {e}")


def main():
    """
    الوظيفة الرئيسية لتحليل الوسائط وتشغيل الماسح.
    """
    parser = argparse.ArgumentParser(description="أداة ذكية لتحليل الهدف باستخدام nmap.")
    parser.add_argument("target", help="عنوان IP الهدف أو اسم النطاق للفحص.")
    args = parser.parse_args()

    target_profiler(args.target)


if __name__ == "__main__":
    main()
