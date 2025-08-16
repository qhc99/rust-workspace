use std::cmp::{max, min};

/// #813
pub fn largest_sum_of_averages(nums: Vec<i32>, k: i32) -> f64 {
    let n = nums.len();

    let mut prefix_sum = vec![0];
    prefix_sum.reserve(n);
    prefix_sum.extend(nums);
    for i in 1..prefix_sum.len() {
        prefix_sum[i] += prefix_sum[i - 1];
    }

    let mut dp: Vec<f64> = Vec::with_capacity(prefix_sum.len());
    prefix_sum.iter().for_each(|v| {
        dp.push(*v as f64);
    });

    for i in 1..dp.len() {
        dp[i] /= i as f64;
    }

    for j in 2..=k {
        for i in (1..=n).rev() {
            for x in (j - 1) as usize..=(i - 1) {
                dp[i] = f64::max(
                    dp[i],
                    dp[x] + (prefix_sum[i] - prefix_sum[x]) as f64 / (i - x) as f64,
                );
            }
        }
    }

    return dp[n];
}

/// #815
pub fn num_buses_to_destination(routes: Vec<Vec<i32>>, source: i32, target: i32) -> i32 {
    use std::collections::{HashMap, HashSet, VecDeque};
    if source == target {
        return 0;
    }
    let cap = routes.iter().map(|v| -> usize { v.len() }).sum();
    let mut bus_stop2_routes: HashMap<i32, Vec<i32>> = HashMap::with_capacity(cap);
    for (route_idx, route_stops) in routes.iter().enumerate() {
        for stop in route_stops.iter() {
            let route_idx = route_idx as i32;
            if !bus_stop2_routes.contains_key(stop) {
                bus_stop2_routes.insert(*stop, vec![route_idx]);
            } else {
                bus_stop2_routes.get_mut(stop).unwrap().push(route_idx);
            }
        }
    }
    let mut queue_routes: VecDeque<(i32, i32)> = VecDeque::new();

    let start_routes = bus_stop2_routes.get(&source);
    let end_routes = bus_stop2_routes.get(&target);
    if start_routes.is_none() || end_routes.is_none() {
        return -1;
    }
    let start_routes = start_routes.unwrap();
    let end_routes = end_routes.unwrap();
    start_routes
        .iter()
        .for_each(|v| queue_routes.push_back((*v, 1)));

    let mut end_routes_set: HashSet<i32> = HashSet::with_capacity(end_routes.len());
    for i in end_routes {
        end_routes_set.insert(*i);
    }
    let mut visited_routes = HashSet::new();
    while !queue_routes.is_empty() {
        let current_route = queue_routes.pop_front().unwrap();
        let count = current_route.1;
        let current_route = current_route.0;
        if end_routes_set.contains(&current_route) {
            return count;
        }
        let current_stops = &routes[current_route as usize];
        for stop in current_stops {
            let next_routes = bus_stop2_routes.get(stop);
            if let Some(next_routes) = next_routes {
                next_routes.iter().for_each(|r| {
                    if !visited_routes.contains(r) {
                        queue_routes.push_back((*r, count + 1));
                        visited_routes.insert(*r);
                    }
                });
            }
        }
    }
    return -1;
}

/// #816
pub fn ambiguous_coordinates(s: String) -> Vec<String> {
    fn valid_comma_split(s: &[u8]) -> bool {
        if s.len() == 1 {
            return true;
        } else {
            return s[0] != b'0' || s[s.len() - 1] != b'0';
        }
    }

    fn dot_split(s1: &[u8], s2: &[u8], v: &mut Vec<String>) {
        let s1 = all_dot_split(s1);
        let s2 = all_dot_split(s2);
        for left in s1.iter() {
            for right in s2.iter() {
                let mut t = vec![b'('];
                t.extend_from_slice(left.as_bytes());
                t.push(b',');
                t.push(b' ');
                t.extend_from_slice(right.as_bytes());
                t.push(b')');
                v.push(String::from_utf8(t).unwrap());
            }
        }
    }

    fn all_dot_split(s: &[u8]) -> Vec<String> {
        use std::str;
        let mut ans = vec![];
        if s.len() == 1 || s[s.len() - 1] == b'0' {
            // add self if no prefix 0 or cannot add dot
            ans.push(str::from_utf8(s).unwrap().to_string());
            return ans;
        } else if s[0] == b'0' {
            // only 0.###
            let mut t = vec![b'0', b'.'];
            t.extend_from_slice(&s[1..]);
            ans.push(String::from_utf8(t).unwrap());
            return ans;
        } else {
            // can split without prefix and suffix 0
            for r_start in 1..s.len() {
                let mut t = s[0..r_start].to_vec();
                t.push(b'.');
                t.extend_from_slice(&s[r_start..]);
                ans.push(String::from_utf8(t).unwrap());
            }
            ans.push(str::from_utf8(s).unwrap().to_string());
            return ans;
        }
    }

    let chrs = s.as_bytes();
    let end = s.len() - 1;
    let mut ans = vec![];
    for right_start in 2..end {
        let s1 = &chrs[1..right_start];
        let s2 = &chrs[right_start..end];
        if valid_comma_split(s1) && valid_comma_split(s2) {
            dot_split(s1, s2, &mut ans)
        }
    }

    return ans;
}

/// #833
pub fn find_replace_string(
    s: String,
    indices: Vec<i32>,
    sources: Vec<String>,
    targets: Vec<String>,
) -> String {
    use std::collections::HashMap;
    let mut ans: Vec<u8> = Vec::with_capacity(s.len());
    let mut s_idx2op_idx: HashMap<i32, i32> = HashMap::new();
    for (i, v) in indices.iter().enumerate() {
        s_idx2op_idx.insert(*v, i as i32);
    }

    let s = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let op_idx = s_idx2op_idx.get(&(i as i32));
        if let Some(op_idx) = op_idx {
            let op_idx = *op_idx as usize;
            let source = &sources[op_idx];
            if i + source.len() <= s.len() && source.as_bytes() == &s[i..i + source.len()] {
                let target = &targets[op_idx];
                ans.extend_from_slice(target.as_bytes());
                i += source.len();
                continue;
            } else {
                ans.push(c);
            }
        } else {
            ans.push(c);
        }
        i += 1;
    }

    return String::from_utf8(ans).unwrap();
}

/// #834
pub fn sum_of_distances_in_tree(n: i32, edges: Vec<Vec<i32>>) -> Vec<i32> {
    use std::collections::VecDeque;

    fn children_count(node: usize, tree: &Vec<Vec<i32>>, descent_count: &mut Vec<i32>) {
        let children = &tree[node];
        if children.is_empty() {
            return;
        }
        for c in children {
            children_count(*c as usize, tree, descent_count);
        }
        for c in children {
            descent_count[node] += descent_count[*c as usize] + 1;
        }
    }

    fn children_sum(node: usize, tree: &Vec<Vec<i32>>, count: &Vec<i32>, sum: &mut Vec<i32>) {
        let children = &tree[node];
        if children.is_empty() {
            return;
        }
        for c in children {
            let c = *c as usize;
            children_sum(c, tree, count, sum);
        }
        for c in children {
            let c = *c as usize;
            sum[node] += sum[c] + count[c] + 1;
        }
    }

    fn parent_sum(
        node: usize,
        inherit_count: i32,
        inherit_sum: i32,
        tree: &Vec<Vec<i32>>,
        descent_count: &Vec<i32>,
        sum: &mut Vec<i32>,
    ) {
        let children = &tree[node];
        sum[node] += inherit_sum + inherit_count;

        for c in children {
            let c = *c as usize;
            let inherit_sum = sum[node] - sum[c] - descent_count[c] - 1;
            let inherit_count = inherit_count + descent_count[node] - descent_count[c];
            parent_sum(c, inherit_count, inherit_sum, tree, descent_count, sum)
        }
    }

    let n = n as usize;
    let mut tree = vec![vec![] as Vec<i32>; n];
    let mut graph = vec![vec![] as Vec<i32>; n];
    let mut descent_count = vec![0; n];
    let mut sum = vec![0; n];
    for v in edges.iter() {
        let n1 = v[0];
        let n2 = v[1];
        graph[n1 as usize].push(n2);
        graph[n2 as usize].push(n1);
    }
    let mut queue: VecDeque<i32> = VecDeque::with_capacity(n);
    queue.push_back(0);
    let mut seen = vec![false; n];
    seen[0] = true;
    while !queue.is_empty() {
        let n = queue.pop_front().unwrap();
        let neighbor = &graph[n as usize];
        for nb in neighbor {
            let nb = *nb;
            if !seen[nb as usize] {
                tree[n as usize].push(nb);
                seen[nb as usize] = true;
                queue.push_back(nb);
            }
        }
    }
    children_count(0, &tree, &mut descent_count);
    children_sum(0, &tree, &descent_count, &mut sum);
    parent_sum(0, 0, 0, &tree, &descent_count, &mut sum);
    return sum;
}

/// #837
pub fn new21_game(n: i32, k: i32, max_pts: i32) -> f64 {
    let mut sum = vec![0f64; (n + 2) as usize];
    let max_pts = max_pts as f64;
    sum[1] = 1f64;
    for i in 1..=min(n, k - 1 + max_pts as i32) {
        let start = max(0, i - max_pts as i32) as usize;
        let end = min(i, k) as usize;
        let p = (sum[end] - sum[start]) / max_pts;
        sum[i as usize + 1] = p + sum[i as usize];
    }
    sum[min(n, k - 1 + max_pts as i32) as usize + 1] - sum[k as usize]
}

/// #838
pub fn push_dominoes(dominoes: String) -> String {
    use std::collections::VecDeque;
    /// at most one 'L' at the end
    fn clear_stack(stack: &mut VecDeque<u8>, ans: &mut Vec<u8>) {
        if stack.is_empty() {
            return;
        }
        if stack[stack.len() - 1] == b'L' {
            let mut r_pos = stack.len() - 1;
            let l_pos = stack.len() - 1;
            while r_pos > 0 && stack[r_pos] != b'R' {
                r_pos -= 1;
            }
            if stack[r_pos] != b'R' {
                ans.append(&mut vec![b'L'; stack.len()]);
                stack.clear();
            } else {
                let _ = stack.split_off(r_pos);
                clear_stack_r_only(stack, ans);
                let half = (l_pos - r_pos).div_ceil(2);
                if (l_pos - r_pos) % 2 == 0 {
                    ans.append(&mut vec![b'R'; half]);
                    ans.push(b'.');
                    ans.append(&mut vec![b'L'; half]);
                } else {
                    ans.append(&mut vec![b'R'; half]);
                    ans.append(&mut vec![b'L'; half]);
                }
            }
        } else {
            clear_stack_r_only(stack, ans);
        }
    }

    fn clear_stack_r_only(stack: &mut VecDeque<u8>, ans: &mut Vec<u8>) {
        while !stack.is_empty() {
            let front = stack.pop_front().unwrap();
            if front != b'R' {
                ans.push(b'.');
            } else {
                ans.append(&mut vec![b'R'; stack.len() + 1]);
                stack.clear();
            }
        }
    }

    let chrs = dominoes.as_bytes();
    let mut stack = VecDeque::<u8>::new();
    let mut ans = Vec::<u8>::new();
    for i in 0..chrs.len() {
        if chrs[i] == b'L' {
            stack.push_back(chrs[i]);
            clear_stack(&mut stack, &mut ans)
        } else if chrs[i] == b'R' {
            clear_stack(&mut stack, &mut ans);
            stack.push_back(chrs[i]);
        } else {
            stack.push_back(chrs[i]);
        }
    }
    clear_stack(&mut stack, &mut ans);
    return String::from_utf8(ans).unwrap();
}
