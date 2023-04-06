#include "highPrecision.h"
#include <algorithm>
const int maxn = 100010;
 
int a[maxn], b[maxn], res[maxn];

std::string HighPrecision::add(std::string s1, std::string s2) {  // under condition: s1,s2>=0
    //  
    int n = s1.length(), m = s2.length();
    for (int i = 0; i < n; i ++) a[i] = s1[n-1-i] - '0';
    for (int i = 0; i < m; i ++) b[i] = s2[m-1-i] - '0';
    int len = std::max(n, m) + 1;
    for (int i = n; i < len; i ++) a[i] = 0;
    for (int i = m; i < len; i ++) b[i] = 0;
    for (int i = 0; i < len; i ++) res[i] = 0;
    //  
    for (int i = 0; i < len; i ++) {
        res[i] += a[i] + b[i];
        if (res[i] >= 10) {
            res[i+1] += res[i] / 10;
            res[i] %= 10;
        }
    }
    //  
    int i = len-1;
    while (res[i] == 0 && i > 0) i --;
    std::string s = "";
    for (; i >= 0; i --) {
        char c = (char) (res[i] + '0');
        s += c;
    }
    return s;
}
 
std::string HighPrecision::sub(std::string s1, std::string s2) {  // under condition: s1>=s2>=0
    //  
    int n = s1.length(), m = s2.length();
    for (int i = 0; i < n; i ++) a[i] = s1[n-1-i] - '0';
    for (int i = 0; i < m; i ++) b[i] = s2[m-1-i] - '0';
    int len = std::max(n, m);
    for (int i = n; i < len; i ++) a[i] = 0;
    for (int i = m; i < len; i ++) b[i] = 0;
    for (int i = 0; i < len; i ++) res[i] = 0;
    //  
    for (int i = 0; i < len; i ++) {
        res[i] += a[i] - b[i];
        if (res[i] < 0) {
            res[i+1] --;
            res[i] += 10;
        }
    }
    //  
    int i = len-1;
    while (res[i] == 0 && i > 0) i --;
    std::string s = "";
    for (; i >= 0; i --) {
        char c = (char) (res[i] + '0');
        s += c;
    }
    return s;
}
 
bool HighPrecision::cmp(std::string s1, std::string s2) {    // under condition: s1,s2 >= 0
    int n = s1.length(), m = s2.length();
    int i;
    for (i = 0; i < n-1 && s1[i] == '0'; i ++);
    s1 = s1.substr(i);
    for (i = 0; i < m-1 && s2[i] == '0'; i ++);
    s2 = s2.substr(i);
    if (s1.length() != s2.length()) return s1.length() < s2.length();
    return s1 < s2;
}
 
std::string HighPrecision::Add(std::string s1, std::string s2) {
    if (s1[0] == '-' && s2[0] == '-') {
        return "-" + add(s1.substr(1), s2.substr(1));
    }
    else if (s1[0] == '-') {
        s1 = s1.substr(1);
        if (cmp(s1, s2) == true) {
            return sub(s2, s1);
        } else {
            return "-" + sub(s1, s2);
        }
    }
    else if (s2[0] == '-') {
        s2 = s2.substr(1);
        if (cmp(s1, s2) == true) {
            return "-" + sub(s2, s1);
        } else {
            return sub(s1, s2);
        }
    }
    else {
        return add(s1, s2);
    }
}
 
std::string HighPrecision::Sub(std::string s1, std::string s2) {
    if (s2[0] == '-') {
        s2 = s2.substr(1);
        return Add(s1, s2);
    }
    else {
        return Add(s1, "-" + s2);
    }
}
 
std::string HighPrecision::multi(std::string s1, std::string s2) {    // under condition: s1,s2>=0
    //  
    int n = s1.length(), m = s2.length();
    for (int i = 0; i < n; i ++) a[i] = s1[n-1-i] - '0';
    for (int i = 0; i < m; i ++) b[i] = s2[m-1-i] - '0';
    int len = n + m;
    for (int i = n; i < len; i ++) a[i] = 0;
    for (int i = m; i < len; i ++) b[i] = 0;
    for (int i = 0; i < len; i ++) res[i] = 0;
    //  
    for (int i = 0; i < n; i ++)
        for (int j = 0; j < m; j ++)
            res[i+j] += a[i] * b[j];
    for (int i = 0; i < len; i ++) {
        res[i+1] += res[i] / 10;
        res[i] %= 10;
    }
    //  
    int i = len-1;
    while (res[i] == 0 && i > 0) i --;
    std::string s = "";
    for (; i >= 0; i --) {
        char c = (char) (res[i] + '0');
        s += c;
    }
    return s;
}
 
std::pair<std::string, std::string> HighPrecision::divide(std::string s1, std::string s2) { // under condition: s1>=0,s2>0
    std::string s = "", t = "";
    int n = s1.length(), m = s2.length();
    bool flag = false;
    for (int i = 0; i < n; i ++) {
        s += s1[i];
        int num = 0;
        while (cmp(s, s2) == false) {
            num ++;
            s = sub(s, s2);
        }
        if (num > 0) {
            flag = true;
            char c = (char)(num + '0');
            t += c;
        }
        else if (flag) {
            t += '0';
        }
    }
    if (t.length() == 0) t = "0";
    while (s[0] == '0' && s.length() > 1) s = s.substr(1);
    return make_pair(t, s);
}