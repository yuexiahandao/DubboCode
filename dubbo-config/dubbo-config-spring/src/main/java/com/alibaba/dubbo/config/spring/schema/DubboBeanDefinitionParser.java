/*
 * Copyright 1999-2011 Alibaba Group.
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.dubbo.config.spring.schema;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.config.TypedStringValue;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.alibaba.dubbo.common.Constants;
import com.alibaba.dubbo.common.extension.ExtensionLoader;
import com.alibaba.dubbo.common.logger.Logger;
import com.alibaba.dubbo.common.logger.LoggerFactory;
import com.alibaba.dubbo.common.utils.ReflectUtils;
import com.alibaba.dubbo.common.utils.StringUtils;
import com.alibaba.dubbo.config.ArgumentConfig;
import com.alibaba.dubbo.config.ConsumerConfig;
import com.alibaba.dubbo.config.MethodConfig;
import com.alibaba.dubbo.config.MonitorConfig;
import com.alibaba.dubbo.config.ProtocolConfig;
import com.alibaba.dubbo.config.ProviderConfig;
import com.alibaba.dubbo.config.RegistryConfig;
import com.alibaba.dubbo.config.spring.ReferenceBean;
import com.alibaba.dubbo.config.spring.ServiceBean;
import com.alibaba.dubbo.rpc.Protocol;

/**
 * AbstractBeanDefinitionParser
 * 
 * @author william.liangf
 * @export
 *
 * 这里必须要说明的是，dubbo的配置可以嵌套的，也可以不是嵌套的。
 * 因为dubbo的配置信息最终会被放置到beanDefinition中的，而所配置的信息会被放到
 * 相应的beanDefinition中的PropertyValue属性中。父标签的属性会被考出放入到子标签的
 * BeanDefinition的PropertyValue属性中，另外会多出ref属性。这样其实配置解析完成之后
 * 父子beanDefinition是在同一级的。
 *
 * 最后大家会发现dubbo：service其实都是com.alibaba.dubbo.config.spring.ServiceBean
 * 而所有的dubbo:reference都是com.alibaba.dubbo.config.spring.ReferenceBean。这样的话，
 * 我们完全可以通过Spring来配置，而不用自定义的Dubbo自定义标签的解析。
 */
public class DubboBeanDefinitionParser implements BeanDefinitionParser {
    
    private static final Logger logger = LoggerFactory.getLogger(DubboBeanDefinitionParser.class);

    // 解析完成后对应bean的类类型
    private final Class<?> beanClass;

    // 一些标签是不是必须的
    private final boolean required;

    public DubboBeanDefinitionParser(Class<?> beanClass, boolean required) {
        this.beanClass = beanClass;
        this.required = required;
    }

    /**
     * 这个是Spring要调用的方法
     * @param element 解析到的元素标签
     * @param parserContext 上下文环境
     * @return
     */
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        return parse(element, parserContext, beanClass, required);
    }
    
    @SuppressWarnings("unchecked")
    private static BeanDefinition parse(Element element, ParserContext parserContext, Class<?> beanClass, boolean required) {
        RootBeanDefinition beanDefinition = new RootBeanDefinition();
        beanDefinition.setBeanClass(beanClass);
        beanDefinition.setLazyInit(false);
        // 取得id标签属性
        String id = element.getAttribute("id");
        if ((id == null || id.length() == 0) && required) {
            // 获取name属性
        	String generatedBeanName = element.getAttribute("name");
        	if (generatedBeanName == null || generatedBeanName.length() == 0) {
        	    if (ProtocolConfig.class.equals(beanClass)) {
                    // ProtocolConfig默认的name是dubbo
        	        generatedBeanName = "dubbo";
        	    } else {
                    // 其他使用默认的interface属性作为name
        	        generatedBeanName = element.getAttribute("interface");
        	    }
        	}
        	if (generatedBeanName == null || generatedBeanName.length() == 0) {
                // name是空的话，那么使用bean的class的名称
        		generatedBeanName = beanClass.getName();
        	}
            id = generatedBeanName; 
            int counter = 2;
            while(parserContext.getRegistry().containsBeanDefinition(id)) {
                id = generatedBeanName + (counter ++);
            }
        }
        if (id != null && id.length() > 0) {
            // 存在相同的beanDefinition报错
            if (parserContext.getRegistry().containsBeanDefinition(id))  {
        		throw new IllegalStateException("Duplicate spring bean id " + id);
        	}
            // 注册相应的beanDefinition
            parserContext.getRegistry().registerBeanDefinition(id, beanDefinition);
            beanDefinition.getPropertyValues().addPropertyValue("id", id);
        }
        /*
        * 处理完成后，就是解决beanDefinition之间的嵌套关系，而这种嵌套关系最终会以ref的形式出现。
         */
        if (ProtocolConfig.class.equals(beanClass)) {
            for (String name : parserContext.getRegistry().getBeanDefinitionNames()) {
                BeanDefinition definition = parserContext.getRegistry().getBeanDefinition(name);
                // 协议实例属性
                PropertyValue property = definition.getPropertyValues().getPropertyValue("protocol");
                if (property != null) {
                    Object value = property.getValue();
                    // 如果协议是ProtocolConfig类型的实例，并且是当前的ProtocolConfig对应的id
                    if (value instanceof ProtocolConfig && id.equals(((ProtocolConfig) value).getName())) {
                        // 附上当前的ProtocolConfig实例
                        definition.getPropertyValues().addPropertyValue("protocol", new RuntimeBeanReference(id));
                    }
                }
            }
        } else if (ServiceBean.class.equals(beanClass)) {
            // 取得class属性，如果存在class属性，就帮忙建立一个对应class的beanDefinition，并且附上相应的信息
            // 在service下的配置，解析完成后同样赋给这个beanDefinition。
            String className = element.getAttribute("class");
            if(className != null && className.length() > 0) {
                RootBeanDefinition classDefinition = new RootBeanDefinition();
                classDefinition.setBeanClass(ReflectUtils.forName(className));
                classDefinition.setLazyInit(false);
                parseProperties(element.getChildNodes(), classDefinition);
                // 将class属性，转化为ref属性。
                beanDefinition.getPropertyValues().addPropertyValue("ref", new BeanDefinitionHolder(classDefinition, id + "Impl"));
            }
        } else if (ProviderConfig.class.equals(beanClass)) {
            // provider 下面可以放入 service标签
            parseNested(element, parserContext, ServiceBean.class, true, "service", "provider", id, beanDefinition);
        } else if (ConsumerConfig.class.equals(beanClass)) {
            // consumer 标签下可以放置 reference 标签
            parseNested(element, parserContext, ReferenceBean.class, false, "reference", "consumer", id, beanDefinition);
        }
        /*
        * 嵌套关系处理完毕
         */

        /*
         * 设置对应的属性，通过setter方法调用。
         */
        Set<String> props = new HashSet<String>();
        ManagedMap parameters = null;
        for (Method setter : beanClass.getMethods()) {
            String name = setter.getName();
            if (name.length() > 3 && name.startsWith("set")
                    && Modifier.isPublic(setter.getModifiers())
                    && setter.getParameterTypes().length == 1) {
                // setter 方法，参数长度是1，并且是public类型的
                Class<?> type = setter.getParameterTypes()[0];
                // 这里是取属性的名称，将第一个字母变成小写的格式，改为-分割
                String property = StringUtils.camelToSplitName(name.substring(3, 4).toLowerCase() + name.substring(4), "-");
                props.add(property);
                Method getter = null;
                try {
                    // 取得getter方法
                    getter = beanClass.getMethod("get" + name.substring(3), new Class<?>[0]);
                } catch (NoSuchMethodException e) {
                    try {
                        getter = beanClass.getMethod("is" + name.substring(3), new Class<?>[0]);
                    } catch (NoSuchMethodException e2) {
                    }
                }
                if (getter == null 
                        || ! Modifier.isPublic(getter.getModifiers())
                        || ! type.equals(getter.getReturnType())) {
                    // 没有合适的getter方法，分析笑一个属性
                    continue;
                }
                if ("parameters".equals(property)) {
                    // 获取子标签的dubbo:property
                    parameters = parseParameters(element.getChildNodes(), beanDefinition);
                } else if ("methods".equals(property)) {
                    parseMethods(id, element.getChildNodes(), beanDefinition, parserContext);
                } else if ("arguments".equals(property)) {
                    // method下可以放置多个argument。
                    parseArguments(id, element.getChildNodes(), beanDefinition, parserContext);
                } else {
                    // 获取Config对应的属性
                    String value = element.getAttribute(property);
                    if (value != null) {
                    	value = value.trim();
                    	if (value.length() > 0) {
                    		if ("registry".equals(property) && RegistryConfig.NO_AVAILABLE.equalsIgnoreCase(value)) {
                                //
                            	RegistryConfig registryConfig = new RegistryConfig();
                            	registryConfig.setAddress(RegistryConfig.NO_AVAILABLE);
                            	beanDefinition.getPropertyValues().addPropertyValue(property, registryConfig);
                            } else if ("registry".equals(property) && value.indexOf(',') != -1) {
                    			parseMultiRef("registries", value, beanDefinition, parserContext);
                            } else if ("provider".equals(property) && value.indexOf(',') != -1) {
                            	parseMultiRef("providers", value, beanDefinition, parserContext);
                            } else if ("protocol".equals(property) && value.indexOf(',') != -1) {
                                parseMultiRef("protocols", value, beanDefinition, parserContext);
                            } else {
                                Object reference;
                                if (isPrimitive(type)) {
                                    if ("async".equals(property) && "false".equals(value)
                                            || "timeout".equals(property) && "0".equals(value)
                                            || "delay".equals(property) && "0".equals(value)
                                            || "version".equals(property) && "0.0.0".equals(value)
                                            || "stat".equals(property) && "-1".equals(value)
                                            || "reliable".equals(property) && "false".equals(value)) {
                                        // 兼容旧版本xsd中的default值
                                        value = null;
                                    }
                                    reference = value;
                                } else if ("protocol".equals(property) 
                                        && ExtensionLoader.getExtensionLoader(Protocol.class).hasExtension(value)
                                        && (! parserContext.getRegistry().containsBeanDefinition(value)
                                                || ! ProtocolConfig.class.getName().equals(parserContext.getRegistry().getBeanDefinition(value).getBeanClassName()))) {
                                    if ("dubbo:provider".equals(element.getTagName())) {
                                        logger.warn("Recommended replace <dubbo:provider protocol=\"" + value + "\" ... /> to <dubbo:protocol name=\"" + value + "\" ... />");
                                    }
                                    // 兼容旧版本配置
                                    ProtocolConfig protocol = new ProtocolConfig();
                                    protocol.setName(value);
                                    reference = protocol;
                                } else if ("monitor".equals(property) 
                                        && (! parserContext.getRegistry().containsBeanDefinition(value)
                                                || ! MonitorConfig.class.getName().equals(parserContext.getRegistry().getBeanDefinition(value).getBeanClassName()))) {
                                    // 兼容旧版本配置
                                    reference = convertMonitor(value);
                                } else if ("onreturn".equals(property)) {
                                    int index = value.lastIndexOf(".");
                                    String returnRef = value.substring(0, index);
                                    String returnMethod = value.substring(index + 1);
                                    reference = new RuntimeBeanReference(returnRef);
                                    beanDefinition.getPropertyValues().addPropertyValue("onreturnMethod", returnMethod);
                                } else if ("onthrow".equals(property)) {
                                    int index = value.lastIndexOf(".");
                                    String throwRef = value.substring(0, index);
                                    String throwMethod = value.substring(index + 1);
                                    reference = new RuntimeBeanReference(throwRef);
                                    beanDefinition.getPropertyValues().addPropertyValue("onthrowMethod", throwMethod);
                                } else {
                                    if ("ref".equals(property) && parserContext.getRegistry().containsBeanDefinition(value)) {
                                        BeanDefinition refBean = parserContext.getRegistry().getBeanDefinition(value);
                                        if (! refBean.isSingleton()) {
                                            throw new IllegalStateException("The exported service ref " + value + " must be singleton! Please set the " + value + " bean scope to singleton, eg: <bean id=\"" + value+ "\" scope=\"singleton\" ...>");
                                        }
                                    }
                                    reference = new RuntimeBeanReference(value);
                                }
		                        beanDefinition.getPropertyValues().addPropertyValue(property, reference);
                            }
                    	}
                    }
                }
            }
        }
        /*
        * 调用setter方法调用属性结束
         */
        NamedNodeMap attributes = element.getAttributes();
        int len = attributes.getLength();
        for (int i = 0; i < len; i++) {
            Node node = attributes.item(i);
            String name = node.getLocalName();
            if (! props.contains(name)) {
                if (parameters == null) {
                    parameters = new ManagedMap();
                }
                String value = node.getNodeValue();
                parameters.put(name, new TypedStringValue(value, String.class));
            }
        }
        if (parameters != null) {
            beanDefinition.getPropertyValues().addPropertyValue("parameters", parameters);
        }
        return beanDefinition;
    }

    private static final Pattern GROUP_AND_VERION = Pattern.compile("^[\\-.0-9_a-zA-Z]+(\\:[\\-.0-9_a-zA-Z]+)?$");
    
    protected static MonitorConfig convertMonitor(String monitor) {
        if (monitor == null || monitor.length() == 0) {
            return null;
        }
        if (GROUP_AND_VERION.matcher(monitor).matches()) {
            String group;
            String version;
            int i = monitor.indexOf(':');
            if (i > 0) {
                group = monitor.substring(0, i);
                version = monitor.substring(i + 1);
            } else {
                group = monitor;
                version = null;
            }
            MonitorConfig monitorConfig = new MonitorConfig();
            monitorConfig.setGroup(group);
            monitorConfig.setVersion(version);
            return monitorConfig;
        }
        return null;
    }
 
    private static boolean isPrimitive(Class<?> cls) {
        return cls.isPrimitive() || cls == Boolean.class || cls == Byte.class
                || cls == Character.class || cls == Short.class || cls == Integer.class
                || cls == Long.class || cls == Float.class || cls == Double.class
                || cls == String.class || cls == Date.class || cls == Class.class;
    }
    
    @SuppressWarnings("unchecked")
	private static void parseMultiRef(String property, String value, RootBeanDefinition beanDefinition,
            ParserContext parserContext) {
    	String[] values = value.split("\\s*[,]+\\s*");
		ManagedList list = null;
        for (int i = 0; i < values.length; i++) {
            String v = values[i];
            if (v != null && v.length() > 0) {
            	if (list == null) {
                    list = new ManagedList();
                }
            	list.add(new RuntimeBeanReference(v));
            }
        }
        beanDefinition.getPropertyValues().addPropertyValue(property, list);
    }

    /**
     * 解析内部标签
     * @param element
     * @param parserContext
     * @param beanClass
     * @param required
     * @param tag
     * @param property
     * @param ref
     * @param beanDefinition
     */
    private static void parseNested(Element element, ParserContext parserContext, Class<?> beanClass, boolean required, String tag, String property, String ref, BeanDefinition beanDefinition) {
        NodeList nodeList = element.getChildNodes();
        if (nodeList != null && nodeList.getLength() > 0) {
            boolean first = true;
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node instanceof Element) {
                    if (tag.equals(node.getNodeName())
                            || tag.equals(node.getLocalName())) {
                        if (first) {
                            first = false;
                            String isDefault = element.getAttribute("default");
                            if (isDefault == null || isDefault.length() == 0) {
                                beanDefinition.getPropertyValues().addPropertyValue("default", "false");
                            }
                        }
                        BeanDefinition subDefinition = parse((Element) node, parserContext, beanClass, required);
                        if (subDefinition != null && ref != null && ref.length() > 0) {
                            subDefinition.getPropertyValues().addPropertyValue(property, new RuntimeBeanReference(ref));
                        }
                    }
                }
            }
        }
    }

    /**
     * 这是为了解析节点的properties属性
     * @param nodeList
     * @param beanDefinition
     */
    private static void parseProperties(NodeList nodeList, RootBeanDefinition beanDefinition) {
        if (nodeList != null && nodeList.getLength() > 0) {
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node instanceof Element) {
                    // <property ... />
                    if ("property".equals(node.getNodeName())
                            || "property".equals(node.getLocalName())) {
                        String name = ((Element) node).getAttribute("name");
                        // 取得name属性
                        if (name != null && name.length() > 0) {
                            String value = ((Element) node).getAttribute("value");
                            String ref = ((Element) node).getAttribute("ref");
                            // value优先，ref次之，都没有报错
                            if (value != null && value.length() > 0) {
                                beanDefinition.getPropertyValues().addPropertyValue(name, value);
                            } else if (ref != null && ref.length() > 0) {
                                beanDefinition.getPropertyValues().addPropertyValue(name, new RuntimeBeanReference(ref));
                            } else {
                                throw new UnsupportedOperationException("Unsupported <property name=\"" + name + "\"> sub tag, Only supported <property name=\"" + name + "\" ref=\"...\" /> or <property name=\"" + name + "\" value=\"...\" />");
                            }
                        }
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    /**
     * 分析自定义标签使用（其实正式的标签也是这样的）
     * 如果是hide属性，那么在key之前加上一个点
     * <dubbo:service><dubbo:property></dubbo:property>........</dubbo:service>
     */
    private static ManagedMap parseParameters(NodeList nodeList, RootBeanDefinition beanDefinition) {
        if (nodeList != null && nodeList.getLength() > 0) {
            ManagedMap parameters = null;
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node instanceof Element) {
                    if ("parameter".equals(node.getNodeName())
                            || "parameter".equals(node.getLocalName())) {
                        if (parameters == null) {
                            parameters = new ManagedMap();
                        }
                        String key = ((Element) node).getAttribute("key");
                        String value = ((Element) node).getAttribute("value");
                        boolean hide = "true".equals(((Element) node).getAttribute("hide"));
                        if (hide) {
                            key = Constants.HIDE_KEY_PREFIX + key;
                        }
                        parameters.put(key, new TypedStringValue(value, String.class));
                    }
                }
            }
            return parameters;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    /**
     * 解析方法的问题
     * <dubbo:service><dubbo:method></dubbo:method>........</dubbo:service>
     */
    private static void parseMethods(String id, NodeList nodeList, RootBeanDefinition beanDefinition,
                              ParserContext parserContext) {
        if (nodeList != null && nodeList.getLength() > 0) {
            ManagedList methods = null;
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node instanceof Element) {
                    Element element = (Element) node;
                    if ("method".equals(node.getNodeName()) || "method".equals(node.getLocalName())) {
                        String methodName = element.getAttribute("name");
                        if (methodName == null || methodName.length() == 0) {
                            throw new IllegalStateException("<dubbo:method> name attribute == null");
                        }
                        if (methods == null) {
                            methods = new ManagedList();
                        }
                        /*
                         * 解析为dubbo:method property,创建beanDefinition，ref指向当前的beanDefinition。
                         */
                        BeanDefinition methodBeanDefinition = parse(((Element) node),
                                parserContext, MethodConfig.class, false);
                        // 生成对应的id
                        String name = id + "." + methodName;
                        // 放入holder里面去，便于读取
                        BeanDefinitionHolder methodBeanDefinitionHolder = new BeanDefinitionHolder(
                                methodBeanDefinition, name);
                        methods.add(methodBeanDefinitionHolder);
                    }
                }
            }
            // 如果没有问题放入beanDefinition的propertyValue中。
            if (methods != null) {
                beanDefinition.getPropertyValues().addPropertyValue("methods", methods);
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    /**
     * method下可以放置多个argument
     */
    private static void parseArguments(String id, NodeList nodeList, RootBeanDefinition beanDefinition,
                              ParserContext parserContext) {
        if (nodeList != null && nodeList.getLength() > 0) {
            ManagedList arguments = null;
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node instanceof Element) {
                    Element element = (Element) node;
                    if ("argument".equals(node.getNodeName()) || "argument".equals(node.getLocalName())) {
                        // 获取index
                        String argumentIndex = element.getAttribute("index");
                        if (arguments == null) {
                            arguments = new ManagedList();
                        }
                        // 解析<dubbo:argument>
                        BeanDefinition argumentBeanDefinition = parse(((Element) node),
                                parserContext, ArgumentConfig.class, false);
                        // 生成id
                        String name = id + "." + argumentIndex;
                        // 放入holder当中
                        BeanDefinitionHolder argumentBeanDefinitionHolder = new BeanDefinitionHolder(
                                argumentBeanDefinition, name);
                        arguments.add(argumentBeanDefinitionHolder);
                    }
                }
            }
            // 放入method的beanDefinition的PropertyValue里面去
            if (arguments != null) {
                beanDefinition.getPropertyValues().addPropertyValue("arguments", arguments);
            }
        }
    }

}