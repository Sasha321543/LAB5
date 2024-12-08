import socket
import os
import sys
import subprocess

def get_local_network_info():
    """Отримує локальну інформацію про мережу: IP-адресу, маску підмережі."""
    try:
        result = subprocess.run(["ip", "addr"], stdout=subprocess.PIPE, text=True)
        for line in result.stdout.split("\n"):
            if "inet " in line and "scope global" in line:
                parts = line.strip().split()
                ip_mask = parts[1]
                ip, mask = ip_mask.split("/")
                return ip, int(mask)
    except Exception as e:
        print(f"Помилка під час отримання інформації про мережу: {e}")
        return None, None

def calculate_ip_range(ip, mask):
    """Розраховує діапазон IP-адрес на основі IP і маски підмережі."""
    mask_bits = 32 - mask
    host_count = 2 ** mask_bits - 2
    base_ip = ip.split(".")
    base_ip[-1] = "0"
    start_ip = ".".join(base_ip)
    end_ip = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{int(base_ip[3]) + host_count}"
    return start_ip, end_ip

def capture_traffic():
    """Перехоплення UDP-трафіку з автоматичним визначенням IP."""
    while True:
        print("\n--- Перехоплення трафіку ---")
        print("1. Почати перехоплення")
        print("2. Аналіз перехоплення трафіку")
        print("3. Повернутися до головного меню")
        choice = input("Виберіть дію: ")

        if choice == "1":
            print("Натисніть Ctrl+C для зупинки.")
            
            # Автоматичне визначення локальної IP-адреси
            ip, mask = get_local_network_info()
            if ip and mask:
                listen_ip = ip  # Використовуємо отриману IP-адресу
            else:
                print("Не вдалося отримати мережеву інформацію.")
                return

            listen_port = 9999  # Використовуємо довільний порт

            suspicious_ips = {}  # Для відстеження підозрілих IP
            alert_limit = 10     # Ліміт для генерації попередження

            try:
                # Створення UDP-сокету
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((listen_ip, listen_port))  # Прив'язка до адреси та порту
                print(f"Прослуховування трафіку на {listen_ip}:{listen_port}...")

                while True:
                    # Отримання даних з мережі
                    data, addr = sock.recvfrom(1024)  # Отримуємо 1024 байти
                    src_ip = addr[0]

                    # Логіка виявлення аномального трафіку
                    suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1
                    print(f"Отримано пакет від {src_ip}, розмір: {len(data)} байт.")

                    if suspicious_ips[src_ip] > alert_limit:
                        print(f"[ПОПЕРЕДЖЕННЯ] Підозрілий трафік від {src_ip} ({suspicious_ips[src_ip]} пакетів)")

            except KeyboardInterrupt:
                print("\nЗупинено перехоплення.")
            except Exception as e:
                print(f"Сталася помилка: {e}")
            finally:
                sock.close()

        elif choice == "2":
            print("\n--- Аналіз перехоплення трафіку ---")
            print("1. Результат перехоплення трафіку")
            print("2. Повернутися до перехоплення трафіку")
            sub_choice = input("Виберіть дію: ")

            if sub_choice == "1":
                print("\n--- Результат перехоплення трафіку ---")
                # Виведення результатів перевірки підозрілих IP
                if suspicious_ips:
                    print("Підозрілі IP-адреси:")
                    for ip, count in suspicious_ips.items():
                        print(f"{ip}: {count} пакетів")
                else:
                    print("Підозрілі IP-адреси не знайдено.")
            elif sub_choice == "2":
                continue
            else:
                print("Неправильний вибір, спробуйте ще раз.")
        
        elif choice == "3":
            return
        else:
            print("Неправильний вибір, спробуйте ще раз.")

def configure_firewall():
    """Автоматичне налаштування брандмауера."""
    while True:
        print("\n--- Налаштування брандмауера ---")
        print("1. Додати правила для довірених IP")
        print("2. Заблокувати підозрілі IP")
        print("3. Повернутися до головного меню")
        choice = input("Виберіть дію: ")

        if choice == "1":
            ip, _ = get_local_network_info()
            if ip:
                trusted_ips = [ip]  # Довіряємо локальному IP
                for ip in trusted_ips:
                    os.system(f"sudo ufw allow from {ip}")
                print(f"Довірені IP {trusted_ips} додані до правил брандмауера.")
            else:
                print("Не вдалося визначити локальну IP-адресу.")
        elif choice == "2":
            blocked_ips = ["192.168.1.100", "192.168.1.101"]  # Приклад заблокованих IP
            for ip in blocked_ips:
                os.system(f"sudo ufw deny from {ip}")
            print(f"Блокування IP {blocked_ips} налаштовано.")
        elif choice == "3":
            return
        else:
            print("Неправильний вибір, спробуйте ще раз.")

def scan_network():
    """Сканування мережі з можливістю переривання."""
    while True:
        print("\n--- Сканування мережі ---")
        print("1. Почати сканування")
        print("2. Повернутися до головного меню")
        choice = input("Виберіть дію: ")

        if choice == "1":
            ip, mask = get_local_network_info()
            if ip and mask:
                start_ip, end_ip = calculate_ip_range(ip, mask)
                print(f"Сканування від {start_ip} до {end_ip}")
                print("Натисність комбінацію клавіш Ctrl+C для переривання сканування")
                ports = [80, 443, 22, 21]  # Найпоширеніші порти

                start = list(map(int, start_ip.split(".")))
                end = list(map(int, end_ip.split(".")))

                active_hosts = []

                try:
                    for i in range(start[3], end[3] + 1):
                        ip = f"{start[0]}.{start[1]}.{start[2]}.{i}"
                        for port in ports:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.5)
                            try:
                                result = sock.connect_ex((ip, port))
                                if result == 0:
                                    print(f"[{ip}:{port}] Порт відкритий")
                                    active_hosts.append((ip, port))
                            except Exception:
                                pass
                            finally:
                                sock.close()
                except KeyboardInterrupt:
                    print("\nСканування перервано користувачем.")
                finally:
                    print(f"Активні хости: {active_hosts}")
            else:
                print("Не вдалося отримати мережеву інформацію.")
        elif choice == "2":
            return
        else:
            print("Неправильний вибір, спробуйте ще раз.")

def main_menu():
    """Головне меню програми."""
    while True:
        print("\n--- Головне меню ---")
        print("1. Перехоплення трафіку")
        print("2. Налаштування брандмауера")
        print("3. Сканування мережі")
        print("4. Вихід")
        choice = input("Виберіть дію: ")

        if choice == "1":
            capture_traffic()
        elif choice == "2":
            configure_firewall()
        elif choice == "3":
            scan_network()
        elif choice == "4":
            print("Завершення програми.")
            sys.exit()
        else:
            print("Неправильний вибір, спробуйте ще раз.")

if __name__ == "__main__":
    main_menu()