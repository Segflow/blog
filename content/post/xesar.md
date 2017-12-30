+++
title = "3DS CTF: Xesar (crypto)"
date = "2017-12-30T13:20:47+01:00"
tags = ["ctf", "crypto", "writeup"]
categories = ["writeup", "crypto"]
author = "Assel meher"
+++

Recently i decided to start playing CTFs again, and since i needed some training before playing a real one, I decided to take a look at some recent CTF in [CTFtime.org](https://ctftime.org/).

And then i found this crypto task with no solution for it yet, and that's why I jumped into it :)

The task was the following:

> We found a paperback with some notes. Help us to find what is this.
> 
> [Access](https://810a5bdaafc6dd30b1d9979215935871.3dsctf.org//challs/crypto/xesar/e1636c027dcec01ce5a5038b48ec70d9.zip)

The zip file contains two files: `encrypted_message.txt` and `draft_xesar.jpg`

The `draft_xesar.jpg` images is the following: 

> {{< figure src="/img/3ds-ctf-2017/draft_xesar.jpg" >}}

It's obvious that the ciphertext we have in the `encrypted_message.txt` is encrypted using this algorithm (but a different key), and our goal is to break it in order to recover the original message and get the flag.

A Pythonic version of it can be written as:

```python
key = "testkey"
plaintext = "the flag is here"
keypass = "testkeytestkeyte" # len(plaintext) == len(keypass)

cipher = "" 
for i in range(len(keypass)):
    x = ord(keypass[i])
    y = rot(keypass, x) # rot(string, int)
    cipher = cipher + chr(ord(plaintext[i]) ^ ord(y[i]))

ciphertext = encode_base64(cipher)
```

So by base64 decoding the encrypted message we get the content of `cipher` which itself is created by XORing every byte in the plaintext by `Y`.

Y only depends on the key, making it act as a key itself, by being a direct derivate of the key we can compute Y even before start encrypting the original text, the following code shows how is that possible: 

```python
key = "testkey"
plaintext = "the flag is here"
keypass = "testkeytestkeyte" # len(plaintext) == len(keypass)


second_key = ""
for i in range(len(keypass)):
    x = ord(keypass[i])
    y = rot(keypass, x) # rot(string, int)
    second_key = second_key + y[i]

cipher = "" 
for i in range(len(plaintext)):
    cipher = cipher + chr(ord(plaintext[i]) ^ ord(second_key[i]))

ciphertext = encode_base64(cipher)
```

This code is easier to understand than the first one because it clearly shows that the encrypted text is the result of XORing the original text with a key (second_key). 

And now our goal is much more simpler, we just need to crack the `second_key` value, which is the key of a simple XOR Cipher. More info about XOR Cipher can be found in this [Wikipedia page](https://en.wikipedia.org/wiki/XOR_cipher)

XOR Cipher can be decoded in two steps:

* Calculate the key length using `Kasiski examination` attack,
* Calculate the key byte per byte via a frequency analysis.

### Calculate the key length
First we need to find the key length, this can be done by performing a [Kasiski examination](https://en.wikipedia.org/wiki/Kasiski_examination), 

Mainly we need to take the ciphertext text, shift it by 1 byte left (of right) to have another ciphertext which we will name ciphertext_shifted1

Now via a simple loop we count how many bytes both `ciphertext` and `ciphertext_shifted1` have in the same position i, let's name this value `same_count`. Here is an example to make it more understandable:

```
ciphertext =          "ABCA"
                          ^
ciphertext_shifted1 = "BCAA"
                          ^
```

The result here is 1, since only at position 4, both the two cipher have the same value (the byte A).

We keep shift the ciphertext again by 2, 3 and so on and every time we calculate the `same_count`. 

The above code will do that for us:

```python
with open("encrypted_message_raw.bin") as f:
    encrypted = f.read()

def shift(data, offset):
    return data[offset:] + data[:offset]

def count_same(a, b):
    count = 0
    for i in range(len(a)):
        if a[i] == b[i]:
            count += 1
    return count

for key_len in range(1, 33): # try multiple key lengths
    freq = count_same(encrypted, shift(encrypted, key_len))
    print ('{0:< 3d} | {1:3d} |'.format(key_len, freq) + '=' * (freq / 4))
```

When we execute this code and feed it our ciphertext we get the following output:

```shell
$ base64 -D encrypted_message.txt > encrypted_message_raw.bin
$ python same_counts.py
 1  | 120 |==============================
 2  |  96 |========================
 3  |  96 |========================
 4  |  83 |====================
 5  |  66 |================
 6  |  85 |=====================
 7  |  82 |====================
 8  | 116 |=============================
 9  | 152 |======================================
 10 | 252 |===============================================================
 11 | 113 |============================
 12 | 107 |==========================
 13 |  97 |========================
 14 |  81 |====================
 15 |  83 |====================
 16 |  89 |======================
 17 | 114 |============================
 18 | 116 |=============================
 19 |  98 |========================
 20 | 261 |=================================================================
 21 | 125 |===============================
 22 | 115 |============================
 23 |  91 |======================
 24 |  75 |==================
 25 |  87 |=====================
 26 |  91 |======================
 27 |  94 |=======================
 28 | 112 |============================
 29 | 108 |===========================
 30 | 225 |========================================================
 31 | 109 |===========================
 32 | 129 |================================
 ```

We notice that `same_count` value is specially high when we shift the ciphertext by 10, 20 and 30. Kasisky says that in this case, where multiple shift values has high `same_count` values the key length is probably the Greatest common divisor (GCD), in this case it's 10. 

So probably the key length is 10. Now let's crack it.


### Key decode
Since the key is repeated to make it's length equal to the original text, every i-th byte of the original is actually XORed with the same key. So by lining up the ciphertext in n columns (remember n in the key length), we will get N differents ciphertexts which can be treated like simple substitution ciphers

Simple substitution ciphers can be broken by doing a simple frequency analysis, for example let's say we have XORed every byte of a message by the byte 0x40, the above code will do that

```python
xor_key = 0x40
data = LONG_PLAIN_TEXT_HERE
cipher = ""
for x in data:
    cipher += chr(ord(x) ^ xor_key)
print(cipher)
```

Frequency analysis can help breaking substitution ciphers here because of the fact that the count of the byte 0x20 in the original text is equal to the count of  0x20 XOR 0x40 (0x60) in the final cipher. So if we have an idea what the most present byte in the original text is we can recover the xor_key from the cipher. 

In the english grammar the letter E is most used one, another candidate is `space`, yes there is lot of spaces in long texts right?

Notice that `frequency analysis` is only effective if the ciphertext is long enough, which is the case here!

First let's start by splitting the cipher text into 10(the key length) columns.

```python
key_len = 10
columns = []
for i in range(0, key_len):
    col = []
    for ch in encrypted[i::key_len]:
        col.append(ch)
    columns.append(col)
```

Now we get the most frequent character in each columns and XOR it with our condidate " ", which is normally the most present character in a long human readable text. The result we get for each column `i` is actually `key[i]`

```python
def most_frequent(text):
    frequency = Counter()
    for x in text:
        frequency[x] += 1
    char, count = frequency.most_common(1)[0]
    return char

key = ""
for col in columns:
    f = most_frequent(col)
    key = key + chr(ord(f) ^ ord(" "))

print(key) # In our case this will print MOIIIG"EMK
```

Now given the key `MOIIIG"EMK` we can try to decode our ciphertext:

```python
def decrypt(c_num, k_num):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(c_num, cycle(k_num)))

print(decrypt(encrypted, key))
```

This will print the text:

```text
LOREM  PSUM DOLO; SIT AMETE CONSECTE=UR ADIPIS*ING ELIT.IMAURIS MA=TIS RISUSIEU SUSCIP TCONSEQU(T. DONEC *ONGUE DAP BUS IPSUME A IMPERD ET EST RU=RUM ID. D&NEC NON I9SUM EGET &RCI VIVER;A PORTA. :ED SAGITT S IPSUM N,C LACUS S<SCIPIT CO'VALLIS. N<LLA IMPER-IET NISI <T DICTUM :USCIPIT. -UIS AC SA.ITTIS LOR,M. PELLEN=ESQUE HAB TANT MORB  TRISTIQU, SENECTUSIET NETUS ,T MALESUA-A FAMES A* TURPIS E.ESTAS. PR&IN BLANDI= NEQUE QU S MAURIS $AXIMUS,V,L PRETIUMINISI PORT(. INTEGERINEC SUSCI9IT URNA.F<SCE IN PH(RETRA LAC<S. FUSCE /EUGIATACIIPSUM ET $OLESTIE. :USPENDISS, NEC ENIMIA MASSA A*CUMSAN BL(NDIT. SUS9ENDISSE C&NVALLIS O;CI SIT AM,T IPSUM C&NSEQUAT, ?EL ALIQUA$ ENIM FEU.IAT. INTE.ER SED CO'DIMENTUM -OLOR, VIT(E CURSUS 'ULLA. VIV(MUS EGET 'UNC A MI 9LACERAT I$PERDIET. 'ULLAM ESTIJUSTO, AL QUET RHON*US ORCI S&DALES, PU%VINAR VEH CULA DOLO;. VIVAMUSIRHONCUS D GNISSIM A;CU EU PHA;ETRA. SUS9ENDISSE E= DOLOR OD O. CURABI=UR IMPERD ET LECTUSISIT AMET %ACINIA VE!ICULA. FU:CE DIAM N SI, GRAVI-A ET SEMP,R SED, EL,IFEND UT $I.MAURIS :ODALES PU;US EFFICI=UR NISL C<RSUS, AT =EMPOR PUR<S PULVINA;. INTEGERIULTRICIESE IPSUM NE* LUCTUS C&NSEQUAT, $AURIS EX =EMPUS MAS:A, NON MA%ESUADA LI.ULA TORTO; UT MASSAG SUSPENDI:SE VEHICU%A NEQUE V TAE LECTU: CONSEQUA=, QUIS CO'GUE ANTE ?OLUTPAT.  NTEGER SE$PER RUTRU$ MAGNA, S T AMET TR STIQUE MA.NA. ALIQU(M ERAT VO%UTPAT. ININON SOLLI*ITUDIN MIG MAECENASIVEHICULA (UGUE PURU:, A TINCI-UNT DOLORIFAUCIBUS :IT AMET. 'ULLAM BLA'DIT EFFIC TUR SAPIE' IN LAORE,T. CRAS V&LUTPAT NE8UE MAGNA,IVOLUTPAT *ONSEQUAT %OREM FERM,NTUM EU. ,TIAM ET L<CTUS METU:. NULLA A= METUS TE%LUS. PELL,NTESQUE R SUS IPSUME PORTA SI= AMET POS<ERE ID, P!ARETRA NO' RISUS. Q<ISQUE EGE= EST VEHI*ULA, TINC DUNT URNAIAT, MOLES=IE MI. SE- UT SEM A%IQUAM, TI'CIDUNT DI(M SED, PO;TTITOR OR*I. SED QU S BLANDITISEM. MAEC,NAS EST P<RUS, VOLU=PAT SIT A$ET DUI EUE MATTIS A<CTOR ELITGCRAS NEC 9URUS SIT (MET URNA 9LACERAT F,UGIAT. NU%LAM DICTU$ LIBERO E=ANTE GRA?IDA, LAOR,ET FACILI:IS URNA E<ISMOD. ET AM ET QUA$ AC NIBH (CCUMSAN M&LESTIE. VVAMUS MOL,STIE EST 8UIS SCELE;ISQUE IAC<LIS. IN V,L ERAT NE8UE. NULLA$ SAGITTISINEC TELLU: ET PLACE;AT. MAURI: MOLESTIEISAPIEN SI= AMET SAP EN PLACER(T, EGET V,HICULA NU%LA DICTUMG NAM PURU: LECTUS, =RISTIQUE 'EC BLANDI= SED, VEH CULA VITA, NULLA. A%IQUAM ERA= VOLUTPATG QUISQUE -ICTUM ELE$ENTUM FEL S FEUGIATITEMPUS. I'TEGER ACC<MSAN RISU: EGET MAX MUS EUISM&D. PELLEN=ESQUE HAB TANT MORB  TRISTIQU, SENECTUSIET NETUS ,T MALESUA-A FAMES A* TURPIS E.ESTAS. VI?AMUS BLAN-IT, NISL  D CURSUS $OLESTIE, ?ELIT PURU: MATTIS L GULA, SITIAMET ELEM,NTUM AUGU, NISL VELITORTOR. P;OIN QUIS <LTRICES N SL. CURAB TUR SEMPE; NULLA NO' ERAT PLA*ERAT, AT ;UTRUM TEL%US PELLEN=ESQUE. AE'EAN PELLE'TESQUE UL%AMCORPER =ELLUS, SO%LICITUDINIPORTTITORILACUS CON-IMENTUM E<.UT NEC D<I MOLLIS ,X VIVERRAICONVALLISG SUSPENDI:SE IN ANT, NON DIAMIULLAMCORP,R VARIUS ,U AC ODIOG DONEC OR*I VELIT, %UCTUS AC %ECTUS QUI:, BIBENDU$ ALIQUET -OLOR. AEN,AN QUAM T<RPIS, PLA*ERAT SED (LIQUAM NO', PLACERA= QUIS LIG<LA. MAURI: AC ANTE 9ORTTITOR %EO TINCID<NT POSUER,. VESTIBU%UM MOLLISIID NULLA ,GET TRIST QUE. MAEC,NAS VIVER;A LACUS A<CTOR LIGU%A POSUEREE EU SUSCI9IT EX HEN-RERIT.ETI(M EFFICIT<R VESTIBU%UM DOLOR,INON PORTT TOR LECTU: PHARETRAIVEL. MAUR S PHARETR( ELEIFENDISCELERISQ<E. PELLEN=ESQUE POR=A SEM LEOE NEC TEMP&R URNA SE$PER SED. :ED DOLOR ,X, PRETIU$ VELENIMISED. THE /LAG IS 3D:{1_H4V3_5YM3_CR1P7065K1LL5}
```

Doesn't this looks familiar? yes it's the famous `Lorem Ipsum` text, but wait somethign is strange here instead of the I we have a space! Actually frequency analysis cannot be 100% accurate so human actions is sometines needed to finish the job.

In this case the key is `MOIIIG"EMK`, and we notice that always at the 7th character the result is wrong, so the frequency analysis in the 7th columns was wrong. But since we know what the 7th character should be we can hardcode it.

The 7th charatcter in the cipher text is 0x02, and in the final decoded text it should be 0x49 (ascii of I), so the 7th character of the key should be 0x02 XOR 0x49 which is 0x4b the ascii code of `K`

With this patch the key becomes `MOIIIGKEMK`, decoding the ciphertext with it and we get the text:

```text
LOREM IPSUM DOLOR SIT AMET, CONSECTETUR ADIPISCING ELIT. MAURIS MATTIS RISUS EU SUSCIPITCONSEQUAT. DONEC CONGUE DAPIBUS IPSUM, A IMPERDIET EST RUTRUM ID. DONEC NON IPSUM EGET ORCI VIVERRA PORTA. SED SAGITTIS IPSUM NEC LACUS SUSCIPIT CONVALLIS. NULLA IMPERDIET NISI UT DICTUM SUSCIPIT. DUIS AC SAGITTIS LOREM. PELLENTESQUE HABITANT MORBI TRISTIQUE SENECTUS ET NETUS ET MALESUADA FAMES AC TURPIS EGESTAS. PROIN BLANDIT NEQUE QUIS MAURIS MAXIMUS,VEL PRETIUM NISI PORTA. INTEGER NEC SUSCIPIT URNA.FUSCE IN PHARETRA LACUS. FUSCE FEUGIATAC IPSUM ET MOLESTIE. SUSPENDISSE NEC ENIM A MASSA ACCUMSAN BLANDIT. SUSPENDISSE CONVALLIS ORCI SIT AMET IPSUM CONSEQUAT, VEL ALIQUAM ENIM FEUGIAT. INTEGER SED CONDIMENTUM DOLOR, VITAE CURSUS NULLA. VIVAMUS EGET NUNC A MI PLACERAT IMPERDIET. NULLAM EST JUSTO, ALIQUET RHONCUS ORCI SODALES, PULVINAR VEHICULA DOLOR. VIVAMUS RHONCUS DIGNISSIM ARCU EU PHARETRA. SUSPENDISSE ET DOLOR ODIO. CURABITUR IMPERDIET LECTUS SIT AMET LACINIA VEHICULA. FUSCE DIAM NISI, GRAVIDA ET SEMPER SED, ELEIFEND UT MI.MAURIS SODALES PURUS EFFICITUR NISL CURSUS, AT TEMPOR PURUS PULVINAR. INTEGER ULTRICIES, IPSUM NEC LUCTUS CONSEQUAT, MAURIS EX TEMPUS MASSA, NON MALESUADA LIGULA TORTOR UT MASSA. SUSPENDISSE VEHICULA NEQUE VITAE LECTUS CONSEQUAT, QUIS CONGUE ANTE VOLUTPAT. INTEGER SEMPER RUTRUM MAGNA, SIT AMET TRISTIQUE MAGNA. ALIQUAM ERAT VOLUTPAT. IN NON SOLLICITUDIN MI. MAECENAS VEHICULA AUGUE PURUS, A TINCIDUNT DOLOR FAUCIBUS SIT AMET. NULLAM BLANDIT EFFICITUR SAPIEN IN LAOREET. CRAS VOLUTPAT NEQUE MAGNA, VOLUTPAT CONSEQUAT LOREM FERMENTUM EU. ETIAM ET LUCTUS METUS. NULLA AT METUS TELLUS. PELLENTESQUE RISUS IPSUM, PORTA SIT AMET POSUERE ID, PHARETRA NON RISUS. QUISQUE EGET EST VEHICULA, TINCIDUNT URNA AT, MOLESTIE MI. SED UT SEM ALIQUAM, TINCIDUNT DIAM SED, PORTTITOR ORCI. SED QUIS BLANDIT SEM. MAECENAS EST PURUS, VOLUTPAT SIT AMET DUI EU, MATTIS AUCTOR ELIT.CRAS NEC PURUS SIT AMET URNA PLACERAT FEUGIAT. NULLAM DICTUM LIBERO ETANTE GRAVIDA, LAOREET FACILISIS URNA EUISMOD. ETIAM ET QUAM AC NIBH ACCUMSAN MOLESTIE. VIVAMUS MOLESTIE EST QUIS SCELERISQUE IACULIS. IN VEL ERAT NEQUE. NULLAM SAGITTIS NEC TELLUS ET PLACERAT. MAURIS MOLESTIE SAPIEN SIT AMET SAPIEN PLACERAT, EGET VEHICULA NULLA DICTUM. NAM PURUS LECTUS, TRISTIQUE NEC BLANDIT SED, VEHICULA VITAE NULLA. ALIQUAM ERAT VOLUTPAT. QUISQUE DICTUM ELEMENTUM FELIS FEUGIAT TEMPUS. INTEGER ACCUMSAN RISUS EGET MAXIMUS EUISMOD. PELLENTESQUE HABITANT MORBI TRISTIQUE SENECTUS ET NETUS ET MALESUADA FAMES AC TURPIS EGESTAS. VIVAMUS BLANDIT, NISL ID CURSUS MOLESTIE, VELIT PURUS MATTIS LIGULA, SIT AMET ELEMENTUM AUGUE NISL VEL TORTOR. PROIN QUIS ULTRICES NISL. CURABITUR SEMPER NULLA NON ERAT PLACERAT, AT RUTRUM TELLUS PELLENTESQUE. AENEAN PELLENTESQUE ULLAMCORPER TELLUS, SOLLICITUDIN PORTTITOR LACUS CONDIMENTUM EU.UT NEC DUI MOLLIS EX VIVERRA CONVALLIS. SUSPENDISSE IN ANTE NON DIAM ULLAMCORPER VARIUS EU AC ODIO. DONEC ORCI VELIT, LUCTUS AC LECTUS QUIS, BIBENDUM ALIQUET DOLOR. AENEAN QUAM TURPIS, PLACERAT SED ALIQUAM NON, PLACERAT QUIS LIGULA. MAURIS AC ANTE PORTTITOR LEO TINCIDUNT POSUERE. VESTIBULUM MOLLIS ID NULLA EGET TRISTIQUE. MAECENAS VIVERRA LACUS AUCTOR LIGULA POSUERE, EU SUSCIPIT EX HENDRERIT.ETIAM EFFICITUR VESTIBULUM DOLOR, NON PORTTITOR LECTUS PHARETRA VEL. MAURIS PHARETRA ELEIFEND SCELERISQUE. PELLENTESQUE PORTA SEM LEO, NEC TEMPOR URNA SEMPER SED. SED DOLOR EX, PRETIUM VELENIM SED. THE FLAG IS 3DS{1_H4V3_50M3_CR1P70_5K1LL5}
```

And that's it, the text is human readable and at the end we can see that the actual flag is `3DS{1_H4V3_50M3_CR1P70_5K1LL5}`

The final code can be found here: [Xesar.py](/code/3ds-ctf-2017/xesar.py)