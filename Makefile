# 编译器
CXX = g++
# 编译选项
CXXFLAGS = -Wall -O2 -std=c++11
# 链接库
LIBS = -libverbs

# 查找当前目录下的所有 .cc 文件并作为源文件
SRCS = $(wildcard *.cc)
# 将所有的 .cc 文件替换为 build/xxx.o 文件
OBJS = $(patsubst %.cc, build/%.o, $(SRCS))
# 输出的可执行文件
TARGET = Simulator

# 默认目标
all: build $(TARGET)

# 创建 build 目录
build:
	mkdir -p build

# 链接目标，生成可执行文件
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# 编译每一个 .cc 文件，输出到 build 目录
build/%.o: %.cc | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 运行目标：构建并运行
run: all
	@if ifconfig | grep -q "192.168.201.4"; then \
		./$(TARGET) 192.168.201.3; \
	else \
		./$(TARGET); \
	fi

capture:
	sudo tcpdump -i mlx5_0 -w capture.pcap

# 清理生成的文件
clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf build
