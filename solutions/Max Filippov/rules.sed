#! /bin/sed -f

#f1ad -- ip
#f1ae -- rol
#f1b2 -- exit
#f1ed -- strlen
#f1ee+ -- text

s/f1ad/_IP_/g
s/f1ae/ROTL/g
s/f1b0/+ONE/g
s/f1b1/-ONE/g
s/f1b2/EXIT/g
s/f1ed/_LEN/g
s/f1ee/T[0]/g
s/f1ef/T[1]/g
s/f1f0/T[2]/g
s/f1f1/T[3]/g
s/f1f2/T[4]/g
s/f1f3/T[5]/g
s/f1f4/T[6]/g
s/f1f5/T[7]/g
s/f1f6/T[8]/g
s/f1f7/T[9]/g
s/f1f8/T[a]/g
s/f1f9/T[b]/g
s/f1fa/T[c]/g
s/f1fb/T[d]/g
s/f1fc/T[e]/g
s/f1fd/T[f]/g

s/NOR(\(....\), \1 => \(....\))/NOT(\1 => \2)/g
s/NOT(\(....\) => \(....\)) ....:NOT(\(....\) => \(....\)) ....:NOR(\2, \4 => \(....\))/AND(\1, \3 => \5)/g
s/NOR(\(....\), \(....\) => \(....\)) ....:NOT(\3 => \(....\))/OR(\1, \2 => \4)/g
s/NOT(\(....\) => \(....\)) ....:NOT(\2 => \(....\))/MOV(\1 => \3)/g
s/=> \(....\)) ....:MOV(\1 => \(....\))/=> \2)/g

s/=> \(....\)) \(....\):MOV(ROTL => \(....\))/=> \1) \2:ROTL(\1 => \3)/g
s/=> \(....\)) \(....\):MOV(ROTL => \(....\))/=> \1) \2:ROTL(\1 => \3)/g

s/ROTL(\(....\) => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \1) ....:ROTL(\1 => \(....\))/ROTR(\1 => \2)/g

s/MOV(\(....\) => \(....\)) ....:\(ROT.\)(\2 => \(....\))/\3(\1 => \4)/g
s/....:MOV(\(....\) => \1) //g

s/MOV(\(....\) => _IP_)/JMP(\1)/g
s/AND(\(....\), \(....\) => \(....\)) ....:NOT(\2 => \(....\)) ....:AND(\(....\), \4 => \(....\)) ....:OR(\3, \6 => _IP_)/JCC(\2 ? \1 : \5)/g
#s/NOT(\(....\) => \(....\)) ....:NOT(\(....\) => \(....\)) ....:AND(\1, \4 => \(....\)) ....:AND(\3, \2 => \(....\)) ....:NOR(\6, \5 => \(....\))/EQ(\1, \3 => \7)/g
s/NOT(\(....\) => \(....\)) ....:NOT(\(....\) => \(....\)) ....:AND(\1, \4 => \(....\)) ....:AND(\3, \2 => \(....\)) ....:OR(\6, \5 => \(....\))/XOR(\1, \3 => \7)/g
#s/NOT(\(....\) => \(....\)) ....:AND(\(....\), \2 => \(....\)) ....:AND(\1, \(....\) => \(....\)) ....:OR(\6, \4 => \(....\))/CMOV(\1 ? \5 : \3 => \7)/g

s/XOR(\(....\), \1 => \1) ....:OR(\1, \(....\) => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:OR(\1, \2 => \1) ....:ROTL(\2 => \2) ....:MOV(\1 => \(....\))/EXP1(\2 => \3)/g

# ADD1(mask, carry, a, b => carry, r)
s/AND(\(....\), \(....\) => ....) ....:AND(\(....\), \2 => ....) ....:AND(\(....\), \2 => \4) ....:XOR(\1, \3 => \(....\)) ....:XOR(\5, \4 => \(....\)) ....:AND(\6, \2 => \6) ....:OR(\6, \(....\) => \7) ....:AND(\1, \3 => \(....\)) ....:AND(\4, \5 => \5) ....:OR(\8, \5 => \4) ....:ROTL(\4 => \4) ....:ROTL(\2 => \2) ....:AND(\4, \2 => \4)/ADD1(\2, \4, \1, \3 => \4, \7)/g

# ADD16(mask, carry, a, b => carry, r)
s/ADD1(\(....\), \(....\), \(....\), \(....\) => \2, \(....\)) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5) ....:ADD1(\1, \2, \3, \4 => \2, \5)/ADD16(\1, \2, \3, \4 => \2, \5)/g

# ADDC(a, b => carry, r)
s/XOR(\(....\), \1 => \1) ....:XOR(\(....\), \2 => \2) ....:MOV(+ONE => \(....\)) ....:ADD16(\3, \1, \(....\), \(....\) => \1, \2)/ADDC(\4, \5 => \1, \2)/g

# ADD(a, b => carry expanded, r)
s/ADDC(\(....\), \(....\) => \(....\), \(....\)) ....:MOV(\4 => \(....\)) ....:EXP1(\3 => \3)/ADD(\1, \2 => \3, \5)/g

s/) /)\n/g