def is_even(num):
    if num%2==0:
        return 'even'
    else:
        return 'odd'
    
for i in range(1,11):
    x=is_even(i)
    print(x)

L=[1,2,3,4]
L.append([1,2])
print(L)