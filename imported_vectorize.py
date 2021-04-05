import time
import re
import json
from statistics import mean
import numpy as np

def sort_behaviors(raw_behaviors):
    raw_behaviors.sort(key = lambda x: x['low'][0]['id'])
    raw_behaviors.sort(key = lambda x: float(x['low'][0]['ts']))
    return raw_behaviors

def strip_unused_keys(behavior_list, unused_keys):
    behavior_index = 0
    for behavior in behavior_list:
        behavior = {key: value for key, value in behavior.items() if key not in unused_keys}
        sub_behavior_index = 0
        for sub_behavior in behavior['low']:
            sub_behavior = {sub_key: sub_value for sub_key, sub_value in sub_behavior.items() if sub_key not in unused_keys}
            behavior['low'][sub_behavior_index] = sub_behavior
            sub_behavior_index += 1
        behavior_list[behavior_index] = behavior
        behavior_index += 1
    return behavior_list

def tokenize(behavior, delimiter):
    behavior_vector = [3]
    prev_matchEnd = 0

    for match in re.finditer(delimiter, behavior):
        matchStart = match.start()
        if (matchStart - prev_matchEnd) > 2 and any(char.isalnum() for char in behavior[prev_matchEnd:matchStart]) and 'low' not in behavior[prev_matchEnd:matchStart]: 
            behavior_vector.append(0)
        behavior_vector.append(int(match.lastgroup[1:]))
        prev_matchEnd = match.end()

    behavior_vector.append(4)

    return behavior_vector

def vectorize(sample, regex_pattern, parent_dir):
    with open('resume_dependencies.txt', 'w') as write_resume:
        write_resume.write('Current sample: \n')
        write_resume.write('{0} \n'.format(sample))
    sample_hash, sample_class = sample
    with open(parent_dir + sample_class + '\\' + sample_hash + '\\sample_for_analysis.apk.json') as sample_path:
        try:
            sample_behaviors = json.load(sample_path)['behaviors']['dynamic']['host']
        except:
            with open('error_hashes.txt', 'a+') as write_errors:
                write_resume.write(sample_hash)
            print("Error loading hash {0}".format(sample_hash))
            return None
    sorted_behaviors = sort_behaviors(sample_behaviors)
    sample_behaviors = []
    # lists are cleared after useage to preserve memory resources

    stripped_behaviors = strip_unused_keys(sorted_behaviors, ['arguments', 'blob', 'parameters', 'id', 'xref', 'ts', 'tid', 'interfaceGroup', 'methodName'])
    sorted_behaviors = []

    string_behaviors = [json.dumps(behavior) for behavior in stripped_behaviors] 
    stripped_behaviors = []

    vectorized_sample = [1]
    for behavior in string_behaviors:
        append_to_vector = tokenize(behavior, regex_pattern)
        for scalar in append_to_vector:
            vectorized_sample.append(scalar)
    vectorized_sample.append(2)

    with open("vectorized_samples/" + sample_class + "/" + sample_hash + ".npy", 'wb') as vector_path:
        np.save(vector_path, vectorized_sample, allow_pickle = False)

    return None