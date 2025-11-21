# 一、更新内容

1、新增php代码执行防御规则，防止读写等危险代码操作，防止蚁剑通过函数操作连接。

2、ssrf逻辑优化：避免127.0.0.1作为访问ip被拦截。

# 二、规则解释

1、有些规则可能重复，检测后的归类是按照代码中先后检测的顺序来判定的。

2、未写csrf检测规则，检测refer、凭证，感觉不好写、作用不大。

3、远程文件包含规则主要归类到了ssrf中。

4、各种伪协议在ssrf和lfi都写有判定规则，可能优先匹配到了ssrf

# 三、具体文章

[MiniWaf使用说明-搓了一个小防火墙](https://mp.weixin.qq.com/s/ZA2ngXxuLg3hTlzBB9LOSg)

[MiniWaf代码说明](https://mp.weixin.qq.com/s/3pi17QVUMULPk-GuLuuxZA)