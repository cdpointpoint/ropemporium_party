
def calc_pext_mask(src, dest):
    mask=0
    bmask=1
    while dest:
        if dest&1 == src&1:
            mask=mask | bmask
            dest>>=1
            print(bin(mask)[2:])
        src>>=1
        bmask<<=1
    return mask



m = calc_pext_mask(0xb0bababa,ord('f'))
print("mask=",bin(m)[2:], hex(m))
    
