Important Notes:

The RSA decryption scheme fails if the message m doesn't meet the condition m<n. 
This is because m≡c^d(modn). if m<n, you'll get exactly the message m when you compute  
c^d mod n. In case m>n, you'll gey a smaller integer that is the equivalent of the message mod n.  
Meaning that you won't recover the original message. Therefore, the unicode value of each character in  
in the string must be less than n=p*q. 
 
