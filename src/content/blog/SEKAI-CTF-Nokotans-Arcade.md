---
author: ch1ko1
title: "SEKAI-CTF / PPC / Nokotan's Arcade"
description: "C++ solution"
pubDate: "Aug 18 2025"
heroImage: "/writeups/la1n.jpg"
---

Problem Statement PDF - https://github.com/project-sekai-ctf/sekaictf-2025/blob/main/ppc/nokotans-arcade/dist/Nokotan's%20Arcade.pdf

Official Writeup - https://github.com/project-sekai-ctf/sekaictf-2025/blob/main/ppc/nokotans-arcade/solution/main_sol.cpp

Solution Code:

```cpp

#include <bits/stdc++.h> // so I don't have to keep writing std:: (gcc only)
using namespace std;

int main()
{
    
    int total_time;
    int number_of_players; // number of lines to read
    int time_per_game;
    
    if (!(cin >> total_time >> number_of_players >> time_per_game)) return 0;
    
    vector<int> arrive(number_of_players), leave(number_of_players);
    vector<long long> importance(number_of_players);
    
    for (int i = 0; i < number_of_players; i++) cin >> arrive[i] >> leave[i] >> importance[i];
    
    int T = total_time - time_per_game + 1; // number of possible start times
    // T will tell us the total number of valid game start times 
    if (T <= 0){
        cout << 0 << "\n"; // no room for any games
        return 0;
    }
    
    // events for doing the sweep line: add at l remove at r+1 
    vector<vector<int>> add(T + 2), rem(T + 2);
    // add[t] contains all player indices that start at time "t"
    // rem[t] contains all player indices that stop at time "t-1"
    
    for (int i = 0; i < number_of_players; ++i){
        int l = arrive[i]; // earliest valid game start
        int r = leave[i] - time_per_game + 1; // last valid game start 
        if (r < l) continue; // cannot fit in the schedule and so this player is ignored
        if (l <= T){
            add[l].push_back(i);
            int rem_pos = min(T + 1, r +1);
            rem[rem_pos].push_back(i);
        }
    }
    
    multiset<long long> ms; // this will keep track of all available player's popularity values at each time, it is automatically sorted by highest popularity.
    vector<long long> w(T + 2, 0); // w[t] = best importance for start t
    for (int t = 1; t <= T; ++t){
        for (int id : add[t]) ms.insert(importance[id]);
        for (int id : rem[t]) {
            auto it = ms.find(importance[id]);
            if (it != ms.end()) ms.erase(it);
        }
        if (!ms.empty()) w[t] = *ms.rbegin();
        else w[t] = 0;
    } 
    
    // DP 
    vector<long long> dp(T + time_per_game + 5, 0); // safe padding range so dp[t+ time_per_game] can exist
    for (int t = T; t>=1; --t){
        long long take = w[t] + dp[t + time_per_game];
        long long skip = dp[t + 1];
        dp[t] = max(skip, take);
    }
    cout << dp[1] << '\n';
        
    return 0;


}

```

## Explanation:

The solution can be broken down into 3 parts:
1. Parsing Inputs
2. Sweep Line
3. Backward Dynamic Programming

### 1. Input Parsing
We read in the first line which is the total_time, number_of_players, time_per_game, this is followed by reading in the players' intervals(stored in 2 int vectors) and their popularity values(stored in a long long vector). We also precompute 'T = total_time - time_per_game + 1' and this gives us the number of possible start times we can use.
### 2. Sweep Line
Before performing the Sweep Line we first prepare event lists (add, rem) to track when a player becomes available or unavailable. To begin the Sweep we scan forward in time from 't = 1' upto 't = T'. At each step we add new players into a multiset(this is automatically sorted) and record the maximum popularity value available at that start time.
### 3. Backward Dynamic Programming
We compute the optimal answer starting from teh end of the schedule. At each 't' we must choose between:
1. Skipping this minute ('dp[t+1]')
2. Taking the best available game for that minute ('w[t] + dp[t+time_per_Game]')

The result will be stored in dp[1] since it always starts at the first 1 minute, that is where the best combination for the full length of total_time is stored.

### Why backwards DP and not forward(like the offical solution)? 
Those are solving 2 different questions. Forward DP would model "time has passed, what can end now?" and the Backwards DP models "what if I start now, what happens later". We used the backward DP because it was easier to write in terms of 'decisions at start times'. They both however work and are valid solutions with the same time complexity too.
