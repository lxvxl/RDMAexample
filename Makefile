# 编译器
CXX = g++
# 编译选项
# - 默认是 release（-O2）
# - 调试：make DEBUG=1（-O0 -g3，并尽量保留栈帧/源码可单步）
DEBUG ?= 0

CXXFLAGS_COMMON = -Wall -std=c++11
CXXFLAGS_RELEASE = -O2
CXXFLAGS_DEBUG = -O0 -g3 -ggdb3 -fno-omit-frame-pointer -fno-inline -fno-optimize-sibling-calls

ifeq ($(DEBUG),1)
	CXXFLAGS = $(CXXFLAGS_COMMON) $(CXXFLAGS_DEBUG)
else
	CXXFLAGS = $(CXXFLAGS_COMMON) $(CXXFLAGS_RELEASE)
endif
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

# 调试构建（等价于 make DEBUG=1）
debug:
	$(MAKE) DEBUG=1 all

# 创建 build 目录
build:
	mkdir -p build

# 链接目标，生成可执行文件
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# 编译每一个 .cc 文件，输出到 build 目录
build/%.o: %.cc | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 运行选项（可通过 make 命令行覆盖）
# 示例: make run N=2 F=3 W=5000
N  ?= 1     # Host 数量 (= QP 数量)
F  ?= 1     # 每个 QP 的 WR 数量
W  ?= 2000  # QP 完成后保持存活时长 (ms)

# 运行目标：构建并运行
run: all
	@if ifconfig | grep -q "192.168.5.122"; then \
		./$(TARGET) -n $(N) -f $(F) -w $(W) 192.168.5.123; \
	else \
		./NotifyReceive.sh N=$(N) F=$(F) W=$(W) > output.txt 2>&1 & \
		./$(TARGET) -n $(N) -f $(F) -w $(W); \
	fi

lrun: all
	@if ifconfig | grep -q "192.168.5.122"; then \
		ltrace -f -S -tt -o ltrace.log ./$(TARGET) -n $(N) -f $(F) -w $(W) 192.168.5.123; \
	else \
		ltrace -f -S -tt -o ltrace.log ./$(TARGET) -n $(N) -f $(F) -w $(W); \
	fi

capture:
	sudo tcpdump -i mlx5_0 -w capture.pcap

# 清理生成的文件
clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf build
