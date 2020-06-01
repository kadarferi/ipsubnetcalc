#!/usr/bin/python
# -*- coding: latin-1 -*-

import sys
import socket


# IP Subnet Calculator

# -------------------------------------------------------------------
# 1. IP address check 
def is_ipv4_address(dotquad):
    """
    Validate an IPv4 address in dotted-quad notation.
    """
    octets = dotquad.split(".")
    try:
        socket.inet_aton(dotquad)
    #        print("Valid IP address: {0}".format(dotquad))
    except socket.error:
        raise ValueError("Invalid IP address: {0}".format(dotquad) )

    return len(octets) == 4 and all(o.isdigit() and 0 <= int(o) < 256 for o in octets)


# -------------------------------------------------------------------

# -------------------------------------------------------------------
# 2. Subnet mask check

def ipv4_mask_len(dotquad):
    """
    Finds the number of bits set in the netmask.
    """
    if not is_ipv4_address(dotquad):
        raise ValueError("Invalid netmask: {0}".format(dotquad))
    a, b, c, d = (int(octet) for octet in dotquad.split("."))
    mask = a << 24 | b << 16 | c << 8 | d

    if mask == 0:
        return 0

    # Count the number of consecutive 0 bits at the right.
    # https://wiki.python.org/moin/BitManipulation#lowestSet.28.29
    m = mask & -mask
    right0bits = -1
    while m:
        m >>= 1
        right0bits += 1

    # Verify that all the bits to the left are 1's
    if mask | ((1 << right0bits) - 1) != 0xffffffff:
        raise ValueError("Invalid netmask: {0}".format(dotquad))
    return 32 - right0bits


# -------------------------------------------------------------------

# 3. Subnet bit number check

def ipv4_mask_len2(slash):
    """Ilyennek kell lennie: 23 """
    #    if not(slash[0] == '/' and slash[1:].isdigit() and 0 <= int(slash[1:]) <= 32):
    if not (slash[:].isdigit() and 0 <= int(slash[:]) <= 32):
        raise ValueError("Invalid netmask: {0}".format(slash))
    return int(slash[:])


# 4.

def subnet_mask_len(mask):
    """A kétféle formátumból kiszámolja a subnet hosszát"""
    if is_ipv4_address(mask):
        l = ipv4_mask_len(mask)
    else:
        l = ipv4_mask_len2(mask)
    return l


# 5. A '/d' -et át kell számolni 'x.x.x.x' alakra

# Decimal to binary

def decimal_to_binarray(n):
    """8 bites számokat 0/1-ok 8 hosszú tömbjévé alakít"""
    bin = []

    def decimal_to_binarray_rec(n):
        if (n > 1):
            # divide with integral result  
            # (discard remainder)  
            decimal_to_binarray_rec(n // 2)

        bin.append(n % 2)

    decimal_to_binarray_rec(n)
    bin = [0] * (8 - len(bin)) + bin
    return bin


# Binary to decimal

power2 = [2 ** (n - 1) for n in range(8, 0, -1)]


def binarray_to_decimal(b):
    """8 bites bináris tömböt decimálissá alakít"""
    # b = np.array(b)
    dec = 0
    for i, p in zip(power2, b):
        dec += i * p
    return dec


# Mask konvertálása

def mask_conv_bin(d):
    """/d - alakot átkonvertálja bináris tömbbé alakúra
    d azt jelenti d darab 1-es bit éa 32-d db 0-s
    parameter: d = szám 1-32-ig"""
    b = [1] * d + [0] * (32 - d)
    # b = [b[0:8], b[8:16], b[16:24], b[24:32]]
    return b


def binmtx_to_dotquad(ba):
    """Subnet mask bináris mátrixát alakítja át decimális x.x.x.x formára"""
    dotquad = "%d.%d.%d.%d" % (binarray_to_decimal(ba[:8]),
                               binarray_to_decimal(ba[8:16]),
                               binarray_to_decimal(ba[16:24]),
                               binarray_to_decimal(ba[24:]))
    return dotquad


def dotquad_to_binmtx(dq):
    """Decimális x.x.x.x alakú ip címet / maskot átalakít bináris tömbbé
    """
    da = dq.split('.')
    da = [int(d) for d in da]
    bm = []
    for d in da:
        b = decimal_to_binarray(d)
        bm = bm + b
    return bm


def binmtx_to_string(ba):
    """Bináris mátrixot bináris folyamatos szöveggé alakít
    pl binmtx_to_string(dotquad_to_binmtx('23.41.21.2')) = 
        '00010111001010010001010100000010'"""
    # b = ba[0] + ba[1] + ba[2] + ba[3]
    b = ba
    y = ""
    for s in b:
        y += str(s)
    return y


def string_to_binmtx(s):
    b = [int(x) for x in s]
    return b


# 6. | beszűrása egy adott helyre a bináris sttringbe

def str_split(s, l):
    """Az s stringbe beszúr egy |-t az l. pozíció után
    pl. str_split('1234567', 3) = '123|4567' """
    s_mod = s[:l] + '|' + s[l:]
    return s_mod


# 7. Bináris mátrixok közt bitenkénti AND művelet számítása

def binmtx_and(bm1, bm2):
    result = []
    for a, b in zip(bm1, bm2):
        result = result + [a * b]
    return result


# ---------------------------------------------------------------------------
# Elvileg megvan minden
# Egy nagy függvényt lehet írni, ami megcsinálja az egészet

def calc_subnet_ip(ip, netmask):
    """Egy host IP-jéből és a netmask-ból meghatározza a hálózat IP címét"""

    # IP cím ellenőrzése
    ip_ok = is_ipv4_address(ip)
    mlen = subnet_mask_len(netmask)
    ip_netmask = binmtx_to_dotquad(mask_conv_bin(mlen))

    # Ha a fentiek lefutottak, akkor nincs hiba
    # írjuk ki az információkat
    info = "A host ip címe: {} {} (/{})".format(ip, ip_netmask, mlen)
    print('\n' + info)

    # Bitsorozattá konvertálás
    ip_bits = binmtx_to_string(dotquad_to_binmtx(ip))
    ip_netmask_bits = binmtx_to_string(dotquad_to_binmtx(ip_netmask))

    print('\nIP Address és Subnet Mask binárisan')
    print(ip_bits)
    print(ip_netmask_bits)

    # Vágás beszűrása a megfelelő helyre a bitsorozatokba
    ip_bits_split = str_split(ip_bits, mlen)
    ip_netmask_bits_split = str_split(ip_netmask_bits, mlen)

    print('\nKritikus bit megjelölése')
    print(ip_bits_split)
    print(ip_netmask_bits_split)

    # Bitenkénti AND végrehajtása a hálózat címéért
    ip_bit_array = dotquad_to_binmtx(ip)
    ip_netmask_bit_array = dotquad_to_binmtx(ip_netmask)

    subnet_bit_array = binmtx_and(ip_bit_array, ip_netmask_bit_array)
    ip_subnet_bits = binmtx_to_string(subnet_bit_array)
    ip_subnet = binmtx_to_dotquad(subnet_bit_array)

    print('\nHálózat címe binárisan')
    print(ip_subnet_bits)

    print('\nHálózat címe decimálisan')
    print(ip_subnet)


# -------------------------------------------
# Hívás terminálból

def main(argv):
    calc_subnet_ip(*argv)


if __name__ == "__main__":
    main(sys.argv[1:])
