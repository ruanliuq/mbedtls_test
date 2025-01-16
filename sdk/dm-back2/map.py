import re
import os

def parse_register_map(header_file):
    register_map = {}
    pattern = re.compile(r"CSR_(\w+)\s*=\s*(0x[0-9A-Fa-f]+)")

    with open(header_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                full_name = "CSR_" + match.group(1).upper()
                short_name = match.group(1).upper()
                lower_name = match.group(1).lower()
                index = int(match.group(2), 16)
                register_map[full_name] = index
                register_map[short_name] = index
                register_map[lower_name] = index
            else:
                # 输出跳过的行的调试信息
                print(f"Skipped line: {line.strip()}")
    return register_map

def parse_instruction_map(header_file):
    instruction_map = {}
    pattern = re.compile(r"#define\s+(\w+)\s+(\d+)")

    with open(header_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                full_name = match.group(1)
                short_name = full_name.split('_')[-1]
                index = int(match.group(2))
                instruction_map[full_name] = index
                instruction_map[short_name] = index

    return instruction_map

def generate_get_register_index_function(register_map):
    function_code = """
int getRegisterIndexByName(const char* name) {
"""
    for name, index in register_map.items():
        function_code += f"""
    if (strcmp(name, "{name}") == 0) return {index};
"""
    function_code += """
    return -1; // 未找到对应的寄存器
}
"""
    return function_code

def generate_get_instruction_index_function(instruction_map):
    function_code = """
int getInstructionIndexByName(const char* name) {
"""
    for name, index in instruction_map.items():
        function_code += f"""
    if (strcmp(name, "{name}") == 0) return {index};
"""
    function_code += """
    return -1; // 未找到对应的指令
}
"""
    return function_code


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    register_map_path = os.path.join(script_dir, 'register_map.h')
    instruction_map_path = os.path.join(script_dir, 'instruction_map.h')

    register_map = parse_register_map(register_map_path)
    instruction_map = parse_instruction_map(instruction_map_path)

    with open(os.path.join(script_dir, 'generated_functions.c'), 'w') as output_file:
        output_file.write("#include <string.h>\n")
        output_file.write("#include \"domain_key.h\"\n")  
        output_file.write("\n")

        # 生成并写入寄存器查找函数
        output_file.write(generate_get_register_index_function(register_map))
        output_file.write("\n")

        # 生成并写入指令查找函数
        output_file.write(generate_get_instruction_index_function(instruction_map))

if __name__ == "__main__":
    main()


