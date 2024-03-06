#!/bin/bash

# xiaosi：3131516796@qq.com
#
# 用途：
# 基于 lightsail 实例快照批量创建
# 批量修改 lightsail 实例 ipv4 防火墙规则
# 随机在可用区中创建

# 标准输出格式
function promptMessages {
    echo -e "\033[92m$@\033[0m"
}

# 错误输出格式
function errorMessages {
    echo -e "\033[91m$@\033[0m"
}

# 系统信息变量
osName=$(grep -oP '^ID="?\K[^"]+' /etc/os-release)
osVersion=$(grep -oP '^VERSION_ID="?\K[^"]+' /etc/os-release)
processorArchitecture=$(arch)

# 判断用户身份与信息信息
if   [[ $(id -u) -ne 0 ]]; then
     errorMessages "错误：当前用不是超级管理员，必须要 root 用户才有权限执行此脚本"
     exit 1
elif [[ ${osName} != "centos" ]]; then
     errorMessages "错误：当前脚本只适用于 centos"
     exit 1
elif [[ ${processorArchitecture} != "x86_64" ]]; then
     errorMessages "错误：当前脚本只适用于 x86 64 架构"
     exit 1
fi

# 用于输出目录名称、实例名称中的杂质、备份aws config 文件中的杂质
randomString="$(date +'%Y%m%d')-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 5)"

# aws config 文件
awsConfigure="${HOME}/.aws/config"

# 创建实例数量计数器
creationSuccessfulNumber=0

# 默认放行端口列表
instancePortjson='"起始端口": 3389, "结束端口": 3389, "协议": "tcp", "白名单": ["0.0.0.0/0"]'
instancePortjson="${instancePortjson}\n\"起始端口\": 22, \"结束端口\": 22, \"协议\": \"tcp\", \"白名单\": [\"0.0.0.0/0\"]"
instancePortjson="${instancePortjson}\n\"类型\": 8, \"代码\": 0, \"协议\": \"icmp\", \"白名单\": [\"0.0.0.0/0\"]"

aws --version &>/dev/null
if [[ $? -ne 0 ]]; then
  promptMessages "安装解压工具 nuzip"
  yum install -y unzip
  promptMessages "开始安装 aws cli 工具"
  curl -sf "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o  "awscliv2.zip"
  if [[ $? -ne 0 ]]; then
     errorMessages "错误：aws cli 工具下载失败"
     exit 2
  fi
  unzip -q awscliv2.zip -d /usr/local/
  bash /usr/local/aws/install  -b /usr/bin
fi

# 安装 jq
jq --version &>/dev/null
if [[ $? -ne 0 ]]; then
  promptMessages "开始安装 json 处理工具 jq"
  curl -sfL https://github.com/jqlang/jq/releases/download/jq-1.7/jq-linux64 -o /usr/bin/jq
  if [[ $? -ne 0 ]]; then
     errorMessages "错误：jq 工具下载失败"
     exit 2
  fi
  chmod +x /usr/bin/jq
fi

# 判断 aws cli 版本是否小于 2
# if [[ $( aws --version | awk -F '[/.]' '{print $2}' ) -le 2 ]]; then
#    echo "aws 版本小于 2"
#    exit 1
# fi
# 安装 aws cli

# 检测 icmp 类型与代码是否正确
function icmpCheck {
  icmpType=${fromPort}
  icmpCode=${toPort}
  if $(echo ${icmpType} | grep -q "^\(0\|8\|9\|10\|13\|14\)$") ; then
    [[ ${icmpCode} -ne 0 ]] &&
    errorMessages "icmp 协议类型为 ${icmpType} 时，代码值必须是 0" &&
    continue
  elif [[ ${icmpType} -eq 3 ]] && [[ ${icmpCode} -gt 15 ]]; then
    errorMessages "icmp 协议类型为 3 时，代码值范围是 0~15"
    continue
  elif [[ ${icmpType} -eq 5 ]] && [[ ${icmpCode} -gt 3 ]]; then
    errorMessages "icmp 协议类型为 5 时，代码值范围是 0~3"
    continue
  elif [[ ${icmpType} -eq 11 ]] && [[ ${icmpCode} -gt 2 ]]; then
    errorMessages "icmp 协议类型为 11 时，代码值为：0、1"
    continue
  elif [[ ${icmpType} -eq 12 ]] && [[ ${icmpCode} -gt 2 ]]; then
    errorMessages "icmp 协议类型为 12 时，代码值为：0、1、2"
    continue
  else
    errorMessages "icmp 协议类型必须是：0、3、5、8、9、10、11、12、13、14、15"
    continue
  fi
}

# 检测 tcp 或 udp 端口号是否满足标准
function tcpAndUdpCheck {
  if [[ -z ${fromPort} ]]; then
    fromPort=${toPort}
  elif [[ ${fromPort} -gt 65535 ]] || [[ ${toPort} -gt 65535 ]]; then
    errorMessages "端口范围超过 65535"
    continue
  elif [[ ${fromPort} -gt ${toPort} ]]; then
    errorMessages "端口范围必须是从小到大，${fromPort} 大于 ${toPort} 是错误的。"
    continue
  fi
}

# 生成 aws configure
function createAwsConfig {
  # 指定 profile 名称
  while true; do
    read -p "指定 aws cli 使用的 profile 名称：" profile
    echo ${profile} | grep -q "^[-a-z0-9_A-Z]\+$"
    if [[ $? -eq 0 ]]; then
       break
    else
       errorMessages "名称只能含有数字、字母、连字符、下划线"
    fi
  done

  # 指定访问密钥 ID 变量
  while true; do
    read -p "指定 aws cli 使用的访问密钥 ID：" awsAccessId
    if [[ $(expr length ${awsAccessId}) -eq 20 ]]; then
       break
    else
      errorMessages "ID 长度不对，检查字符串是否正确（多或少）"
    fi
  done

  # 指定访问密钥 KEY 变量
  while true; do
  read -p "指定 aws cli 使用的访问密钥 KEY：" awsAccessKey
    if [[ $(expr length ${awsAccessKey}) -eq 40 ]]; then
       break
    else
      errorMessages "KEY 长度不对，检查字符串是否正确（多或少）"
    fi
  done
  # 生成 aws configure
  mkdir -p ~/.aws
  echo ""                                         >> ${awsConfigure}
  echo "[profile ${profile}]"                     >> ${awsConfigure}
  echo "output = json"                            >> ${awsConfigure}
  echo "aws_access_key_id = ${awsAccessId}"       >> ${awsConfigure}
  echo "aws_secret_access_key = ${awsAccessKey}"  >> ${awsConfigure}
}

# 获取 aws config
if [[ -s ${awsConfigure} ]]; then
  profile=$(sed "/[[:space:]]*\[\(profile[[:space:]]*\)\?.\+\]/! d; \
     s/.*\[\(profile[[:space:]]*\)\?\(.*\)\].*/\2/" ${awsConfigure} \
     | awk '{print NR"."$0}')

  if [[ -z ${profile} ]] ; then
    errorMessages "aws configure 不存在，开始创建配置文件"
    createAwsConfig
  else
    while true; do
      promptMessages "0.新建 ${profile}" | sed 's/ /\n/g'
      read -p "选择拥有操作权限的配置项：" n
      echo ${n} | grep -q "^[0-9]\+$"
      if [[ $? -ne 0 ]]; then
        errorMessages "错误，序列号必须是数字"
        continue
      fi
      if [[ ${n} -eq 0 ]]; then
        promptMessages "开始创建配置文件"
        createAwsConfig
        break
      fi
      echo "${profile}" | sed 's/ /\n/g' | grep -q "^${n}."
      if [[ $? -eq 0 ]]; then
        profile=$(echo "0.新建 ${profile}" | sed 's/ /\n/g' \
            | grep -Po "(?<=^${n}.).*")
        break
      else
        errorMessages "没有该序列号：${n}，重新选择"
      fi
    done
  fi
else
    errorMessages "aws configure 不存在，开始创建配置文件"
    createAwsConfig
fi

# 打印选项列表
promptMessages " 0.退出脚本"
promptMessages " 1.欧洲    （爱尔兰）         (eu-west-1)"
promptMessages " 2.欧洲    （英国-伦敦）      (eu-west-2)"
promptMessages " 3.欧洲    （法国-巴黎）      (eu-west-3)"
promptMessages " 4.欧洲    （德国-法兰克福）  (eu-central-1)"
promptMessages " 5.欧洲    （瑞典-斯德哥尔摩）(eu-north-1)"
promptMessages " 6.加拿大  （蒙特利尔）       (ca-central-1)"
promptMessages " 7.亚太地区（孟买）           (ap-south-1)"
promptMessages " 8.亚太地区（新加坡）         (ap-southeast-1)"
promptMessages " 9.亚太地区（日本-东京）      (ap-northeast-1)"
promptMessages "10.亚太地区（韩国-首尔）      (ap-northeast-2)"
promptMessages "11.亚太地区（澳大利亚-悉尼）  (ap-southeast-2)"
promptMessages "12.美国东部（俄亥俄）         (us-east-2)"
promptMessages "13.美国西部（俄勒冈）         (us-west-2)"
promptMessages "14.美国东部（弗吉尼亚北部）   (us-east-1)"
# 指定区域变量
while true; do
    read -p "选择创建区域的序列号（1-14）：" awsRegion
    # 检查用户选择是否有效，并定义区域变量以及可用区列表
    case ${awsRegion} in
         0) exit ;;
         1)
            awsRegion="eu-west-1"
            availabilityZoneList="a\nb\nc"
            break ;;
         2)
            awsRegion="eu-west-2"
            availabilityZoneList="a\nb\nc"
            break ;;
         3)
            awsRegion="eu-west-3"
            availabilityZoneList="a\nb\nc"
            break ;;
         4)
            awsRegion="eu-central-1"
            availabilityZoneList="a\nb\nc"
            break ;;
         5)
            awsRegion="eu-north-1"
            availabilityZoneList="a\nb\nc"
            break ;;
         6)
            awsRegion="ca-central-1"
            availabilityZoneList="a\nb\nd"
            break ;;
         7)
            awsRegion="ap-south-1"
            availabilityZoneList="a\nb\nc"
            break ;;
         8)
            awsRegion="ap-southeast-1"
            availabilityZoneList="a\nb\nc"
            break ;;
         9)
            awsRegion="ap-northeast-1"
            availabilityZoneList="a\nc\nd"
            break ;;
        10)
            awsRegion="ap-northeast-2"
            availabilityZoneList="a\nb\nc\nd"
            break ;;
        11)
            awsRegion="ap-southeast-2"
            availabilityZoneList="a\nb\nc"
            break ;;
        12)
            awsRegion="us-east-2"
            availabilityZoneList="a\nb\nc"
            break ;;
        13)
            awsRegion="us-west-2"
            availabilityZoneList="a\nb\nc\nd"
            break ;;
        14)
            awsRegion="us-east-1"
            availabilityZoneList="a\nb\nc\nd\ne\nf"
            break ;;
        *) errorMessages "没有该序列号：${awsRegion}，重新选择" ;;
    esac
done




# 获取快照列表
instanceSnapshotList=$(aws lightsail get-instance-snapshots \
  --region ${awsRegion} \
  --profile ${profile} | jq -r \
  '.instanceSnapshots | map(.name) | sort | to_entries[] | "\(.key + 1). \(.value)"')

# 选择快照
if [[ ${#instanceSnapshotList} -gt 0 ]]; then
    promptMessages ${instanceSnapshotList} | sed 's/ \([0-4]\+.\)/\n\1/g'
    while true; do
      # 待：直接回车也会进入下一步
      read -p "选择用于创建实例的快照序列号：" n
      echo ${instanceSnapshotList} | sed 's/ \([0-4]\+.\)/\n\1/g' | grep -q "^${n}. "
      if [[ $? -eq 0 ]]; then
         instanceSnapshotName=$(echo ${instanceSnapshotList} \
          | sed 's/ \([0-4]\+.\)/\n\1/g' | grep -Po "(?<=^${n}. ).*")
         break
      else
         errorMessages "没有该序列号：${n}，重新选择"
      fi
    done
else
    errorMessages "${awsRegion} 区域没有快照或 aws 命令获取快照失败"
    exit 3
fi


# 打印规格列表
promptMessages '序列号  月价格(美元)  vcpu  内存(G)  磁盘(G)  月流量(G)  操作系统'
promptMessages '1       3.5           2     0.5      20       1024       LINUX_UNIX'
promptMessages '2       5.0           2     1.0      40       2048       LINUX_UNIX'
promptMessages '3       10.0          2     2.0      60       3072       LINUX_UNIX'
promptMessages '4       20.0          2     4.0      80       4096       LINUX_UNIX'
promptMessages '5       40.0          2     8.0      160      5120       LINUX_UNIX'
promptMessages '6       80.0          4     16.0     320      6144       LINUX_UNIX'
promptMessages '7       160.0         8     32.0     640      7168       LINUX_UNIX'
promptMessages '8       8.0           2     0.5      30       1024       WINDOWS'
promptMessages '9       12.0          2     1.0      40       2048       WINDOWS'
promptMessages '10      20.0          2     2.0      60       3072       WINDOWS'
promptMessages '11      40.0          2     4.0      80       4096       WINDOWS'
promptMessages '12      70.0          2     8.0      160      5120       WINDOWS'
promptMessages '13      120.0         4     16.0     320      6144       WINDOWS'
promptMessages '14      240.0         8     32.0     640      7168       WINDOWS'

# 指定实例规格
while true; do
  # 选择规格列表
  read -p "选择实例规格，注意系统类型（1-14）：" bundleId
  case "${bundleId}" in
    1)
      bundleId="nano_3_0"
      instanceSpecification="LINUX_UNIX 2核 0.5G内存 20G硬盘 3.5/月"
      break ;;
    2)
      bundleId="micro_3_0"
      instanceSpecification="LINUX_UNIX 2-40-1.0(5.0/月)"
      break ;;
    3)
      bundleId="small_3_0"
      instanceSpecification="LINUX_UNIX-10.0-2-60-2.0(10.0/月)"
      break ;;
    4)
      bundleId="medium_3_0"
      instanceSpecification="LINUX_UNIX-20.0-2-80-4.0(20.0/月)"
      break ;;
    5)
      bundleId="large_3_0"
      instanceSpecification="LINUX_UNIX-40.0-2-160-8.0(40.0/月)"
      break ;;
    6)
      bundleId="xlarge_3_0"
      instanceSpecification="LINUX_UNIX-80.0-4-320-16.0(80.0/月)"
      break ;;
    7)
      bundleId="2xlarge_3_0"
      instanceSpecification="LINUX_UNIX-160.0-8-640-32.0(160.0/月)"
      break ;;
    8)
      bundleId="nano_win_3_0"
      instanceSpecification="WINDOWS-8.0-2-30-0.5(8.0/月)"
      break ;;
    9)
      bundleId="micro_win_3_0"
      instanceSpecification="WINDOWS-12.0-2-40-1.0(12.0/月)"
      break ;;
    10)
      bundleId="small_win_3_0"
      instanceSpecification="WINDOWS-20.0-2-60-2.0(20.0/月)"
      break ;;
    11)
      bundleId="medium_win_3_0"
      instanceSpecification="WINDOWS-40.0-2-80-4.0(40.0/月)"
      break ;;
    12)
      bundleId="large_win_3_0"
      instanceSpecification="WINDOWS-70.0-2-160-8.0(70.0/月)"
      break ;;
    13)
      bundleId="xlarge_win_3_0"
      instanceSpecification="WINDOWS-120.0-4-320-16.0(120.0/月)"
      break ;;
    14)
      bundleId="2xlarge_win_3_0"
      instanceSpecification="WINDOWS-240.0-8-640-32.0(240.0/月)"
      break ;;
    *) errorMessages "错误的序列号：${bundleId}" ;;
  esac
done

# 指定实例数变量
while true; do
  read -p "创建实例数量，默认为 1：" instancesNumber
  instancesNumber=${instancesNumber:=1}
  if [[ ${instancesNumber} =~ ^[0-9]+$ ]] && [[ ${instancesNumber} -ge 0 ]] ; then
      break
  else
      errorMessages "${instancesNumber} 必须是大于 0 的整数"
  fi
done


# 获取 ssh 公钥列表
sshKeyList=$(aws lightsail get-key-pairs \
  --region ${awsRegion} \
  --profile ${profile} | jq -r \
  '.keyPairs | map(.name) | sort | to_entries[] | "\(.key + 1). \(.value)"')

# 选择公钥
if [[ ${#sshKeyList} -gt 0 ]]; then
    echo ${sshKeyList} | sed 's/ \([0-4]\+.\)/\n\1/g'
    while true; do
      read -p "选择用于创建实例的公钥序列号：" n
      echo ${sshKeyList} | sed 's/ \([0-4]\+.\)/\n\1/g' | grep -q "^${n}. "
      if [[ $? -eq 0 ]]; then
         sshKeyName=$(echo ${sshKeyList} \
             | sed 's/ \([0-4]\+.\)/\n\1/g' | grep -Po "(?<=^${n}. ).*")
         break
      else
         errorMessages "没有该序列号：${n}"
      fi
    done
else
   promptMessages "${awsRegion} 区域没有自定义 ssh 公钥，将使用默认公钥"
   sshKeyName="LightsailDefaultKeyPair"
fi






# 实例白名单规则提示
promptMessages "添加端口规则：“端口”(0到65535) + “/” + “协议”(tcp或udp或icmp)"
echo "示例：22/tcp"
promptMessages "添加端口规则：对于 tcp或udp 可以使用 “—” 表示tcp或udp端口范围。必须是从小到大"
promptMessages "添加端口规则：对于 imcp 协议使用-分隔 ICMP 类型和代码"
echo "示例：8080-8088/tcp"
echo "示例，ping 命令使用的 icmp ：8-0/icmp"
promptMessages "添加端口规则：可以使用 “=” 只允许指定ip访问（支持CIDR格式)"
echo "示例：22/tcp=192.178.23.22"
echo "示例：122=233/tcp=192.168.0.0/16"
# 添加防火墙
while true; do
  # 提示
  promptMessages '添加：根据上面说明，指定实例放行端口'
  promptMessages '保存：输入 yes 可保存规则'
  promptMessages '删除：输入 规则编号+d，可删除规则。如 1d 删除第1条规则'
  promptMessages '================== 现有规则：=================='
  echo -e ${instancePortjson} | awk '{print NR". "$0}'
  promptMessages '==============================================='
  read -p "根据说明执行添加、删除、保存规则操作：" instancePortTxt

  if [[ -z ${instancePortTxt} ]]; then
    continue
  # 保存规则，并修改为 json 格式
  elif [[ ${instancePortTxt} == "yes" ]]; then
    instancePortjson=${instancePortjson//类型/fromPort}
    instancePortjson=${instancePortjson//起始端口/fromPort}
    instancePortjson=${instancePortjson//代码/toPort}
    instancePortjson=${instancePortjson//结束端口/toPort}
    instancePortjson=${instancePortjson//协议/protocol}
    instancePortjson=${instancePortjson//白名单/cidrs}
    instancePortjson=$(echo -e ${instancePortjson} | sed 's/^/{/ ; s/$/},/')
    instancePortjson=${instancePortjson//\n/}
    instancePortjson=${instancePortjson%,}
    instancePortjson="[${instancePortjson}]"
    instancePortjson=$(echo ${instancePortjson} | jq -c 'unique')
    break
  # 删除规则
  elif $(echo ${instancePortTxt} | grep -q "^[1-9]\+d$") ; then
    instancePortjson=$(echo -e ${instancePortjson} | sed "${instancePortTxt}"| sed ':a;N;$!ba;s/\n/\\n/g')
    continue
  fi

  # 基础检测语法是否满足
  echo ${instancePortTxt} |\
  grep -q "^\([[:digit:]]\+-\)\?[[:digit:]]\+/\(udp\|tcp\|icmp\)\
\(=\([[:digit:]]\+\.\)\{3\}[[:digit:]]\+\(/[[:digit:]]\+\)\?\)\?$"

  if [[ $? -ne 0 ]]; then
    errorMessages "格式不对，无法解析 ${instancePortTxt}"
    continue
  fi

  fromPort=$(echo ${instancePortTxt} | grep -oP "^[0-9]*(?=-)")
  toPort=$(echo ${instancePortTxt} | grep -oP "[0-9]+(?=/(tcp|udp|icmp))")
  protocol=$(echo ${instancePortTxt} | grep -oP "(?<=${toPort}/)(tcp|udp|icmp)")
  cidrIP=$(echo ${instancePortTxt} | grep -oP "(?<=${protocol}=)(\d+\.){3}\d+")
  cidrMask=$(echo ${instancePortTxt} | grep -oP "(?<=${cidrIP}/)\d+")

  # 判断 CIDR 格式
  if [[ -z ${cidrIP} ]]; then
    cidrIP="0.0.0.0"
    cidrMask="0"
  elif [[ ${cidrMask} -gt 32 ]]; then
    errorMessages "CIDR IPv4 前缀值不能大于 32"
    continue
  else
    for n in $(echo ${cidrIP} | awk -F "." '{print $1,$2,$3,$4}') ; do
      echo $n | grep -q "^[1-9][0-9]\?$\|^1[0-9]\{1,2\}$\|^2[0-5]\{1,2\}$" || \
      errorMessages "IPv4 格式不对"
      continue
    done
  fi

  # 判断协议
  if [[ ${protocol} == "icmp" ]]; then
    icmpCheck
    instancePortjson="${instancePortjson}\n\"类型\": ${fromPort}, \"代码\": ${toPort}, \"协议\": \"${protocol}\", \"白名单\": [\"${cidrIP}/${cidrMask}\"]"
  else
    tcpAndUdpCheck
    instancePortjson="${instancePortjson}\n\"起始端口\": ${fromPort}, \"结束端口\": ${toPort}, \"协议\": \"${protocol}\", \"白名单\": [\"${cidrIP}/${cidrMask}\"]"
  fi
done

# 指定实例名称前缀变量
read -p "指定实例名称前缀（推荐格式：账号别名-用途-地区）：" instanceNamePrefix


# 用户确认信息
promptMessages "==================信息展示：====================="
promptMessages "区域：${awsRegion}"
promptMessages "快照名：${instanceSnapshotName}"
promptMessages "实例规格：${instanceSpecification}"
promptMessages "实例数量：${instancesNumber}"
promptMessages "ssh 公钥文件名：${sshKeyName}"
# promptMessages "放行端口列表："
# promptMessages "${instancePortTxt}"
promptMessages "实例名称示例：${instanceNamePrefix}-${availabilityZone}a1-${randomString}"
promptMessages "================================================="
while true; do
  read -p "如果上面信息正确，输入 yes 开始创建实例，或输入 no 退出脚本：" confirmationInformation
  if   [[ ${confirmationInformation} == "yes" ]]; then
       break
  elif [[ ${confirmationInformation} == "no" ]]; then
       exit 1
  fi
done

# 基于lightsail 实例快照批量创建
promptMessages "开始创建实例："
# 输出目录
mkdir -p ${randomString}
echo "[" > ${randomString}-create-instances.json
for n in $(seq -w ${instancesNumber}); do
    # 随机指定可用区
    availabilityZone=$(echo -e ${availabilityZoneList} | shuf -n 1)
    aws lightsail create-instances-from-snapshot \
    --region ${awsRegion} \
    --profile ${profile} \
    --instance-names ${instanceNamePrefix}-${randomString}-${availabilityZone}${n} \
    --availability-zone ${awsRegion}${availabilityZone} \
    --instance-snapshot-name ${instanceSnapshotName} \
    --bundle-id ${bundleId} \
    --key-pair-name ${sshKeyName} \
    --ip-address-type ipv4 >> ${randomString}-create-instances.json

    if  [[ $? -eq 0 ]]; then
        creationSuccessfulNumber=$((creationSuccessfulNumber + 1 ))
        echo "," >> ${randomString}-create-instances.json
        instancesList="${instancesList} ${instanceNamePrefix}-${randomString}-${availabilityZone}${n}"
        promptMessages "实例创建成功：${instanceNamePrefix}-${randomString}-${availabilityZone}${n}"
    else
        errorMessages "实例创建失败：${instanceNamePrefix}-${randomString}-${availabilityZone}${n}"
        errorMessages "放弃继续创建实例"
        break
    fi
done
sed -i '$ s/,/]/' ${randomString}-create-instances.json

# 如果没有成功创建实例，则清理文件并退出脚本
if [[ ${creationSuccessfulNumber} -gt 0 ]]; then
   promptMessages "已创建实例数量：${creationSuccessfulNumber}"
   promptMessages "此脚本将等待 90 秒，避免有实例没有完成启动"
   sleep 90s
else
   rm -rf ${randomString}
   exit 3
fi

# 放行实例端口
promptMessages "开始放行实例端口"
echo "[" > ${randomString}-put-instance-public-ports.json

for instancesName in ${instancesList[@]} ; do
  aws lightsail put-instance-public-ports \
      --region ${awsRegion} \
      --profile ${profile} \
      --instance-name ${instancesName} \
      --port-infos ${instancePortjson} \
      >> ${randomString}-put-instance-public-ports.json
  if  [[ $? -eq 0 ]]; then
      promptMessages "${instancesName} 实例端口添加成功"
      putInstancePublicPortsOk="${putInstancePublicPortsOk} ${instancesName}"
  else
      putInstancePublicPortsFail="${putInstancePublicPortsFail} ${instancesName}"
  fi
  echo "," >> ${randomString}-put-instance-public-ports.json
done
sed -i '$ s/,/]/' ${randomString}-put-instance-public-ports.json


# 获取实例公网 IP
promptMessages "可以尝试连接以下 IP："
for instancesName in ${putInstancePublicPortsOk[@]}; do
  aws lightsail get-instance \
      --region ${awsRegion} \
      --profile ${profile} \
      --instance-name ${instancesName} \
      | jq -r ".instance.publicIpAddress"
done

# 输出添加端口失败的实例名
if [[ -n ${putInstancePublicPortsFail} ]] ; then
  errorMessages "以下实例添加端口失败，请手动排查："
  errorMessages ${putInstancePublicPortsFail} | sed 's/ /\n/g'
fi

# 安全提示
promptMessages   ======================================================
echo -e "\033[91m 脚本明码执行，为了安全。有必要删除本次使用的访问密钥。\033[0m"
promptMessages   ======================================================

read -p "输入 yes 立即删除本次使用的访问密钥：" deleteAccessKey
if [[ ${deleteAccessKey} == "yes" ]]; then

   # 在 aws 上删除访问密钥
   if [[ -n ${awsAccessId} ]]; then
      aws iam delete-access-key \
      --profile ${profile} \
      --access-key-id ${awsAccessId}
   else
      awsAccessId=$(sed -n "/[[:space:]]*\[profile ${profile}\]/,\
          /[[:space:]]\?\[profile.*/{/aws_access_key_id/p}" ${awsConfigure})
      awsAccessId=${awsAccessId#*=}
      aws iam delete-access-key \
      --profile ${profile} \
      --access-key-id ${awsAccessId}
   fi

   # 在 cofnig 中删除访问密钥
   sed -i "/[[:space:]]*\[profile ${profile}\]/,\
     /[[:space:]]\?\[profile.*/ \
     {/[[:space:]]\?\[profile.*/! d; \
     /${profile}/d}" ${awsConfigure}
  
    promptMessages "======================= 删除完成 ======================="
else
   echo "妥善保管访问密钥"
fi
