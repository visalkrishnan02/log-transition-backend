@router.get("/timeline-test/{subcatalog_id}", response_model=dict)
def get_subcatalog_topics_by_event_type(subcatalog_id: int, db: Session = Depends(get_db)):
    
    subcatalog = db.query(SubCatalog).filter(SubCatalog.id == subcatalog_id).first()
    if not subcatalog:
        raise HTTPException(status_code=404, detail="Subcatalog not found")
    
    service_type = db.query(ServiceType).filter(ServiceType.id == subcatalog.service_type_id).first()
    if not service_type:
        raise HTTPException(status_code=404, detail="Service Type not found")
    
    topics = db.query(Topic).filter(Topic.subcatalog_id == subcatalog_id).all()

    topic_summary = ""
    for topic in topics:
        topic_summary += f"The topic name is {topic.name}. "
        topic_summary += f"The topic description is {topic.description}. "
    
    sub_catalog_name = subcatalog.sub_catalog_name

    kt_percent = getattr(service_type, "kt_session")
    fwd_percent = getattr(service_type, "fwd_shadow")
    rev_percent = getattr(service_type, "rev_shadow")
    cutover_percent = getattr(service_type, "cutover")

    try:
        model = AzureChatOpenAI(model="gpt-4o", api_version='2024-02-15-preview')
        prompt_template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are an expert analyst specializing in evaluating services and their associated tasks."),
                (
                    "human", 
                    (
                        "Given is the service name, {sub_catalog_name} and task summary of this service, {topic_summary}.\n"
                        "Given the following details about the service and its tasks, analyze and provide the following:\n"
                        "1. The criticality of the service and its tasks. Explain why they are critical or not.\n"
                        "2. The complexity of the tasks, considering the processes, dependencies, and technical requirements.\n"
                    )
                ),
            ]
        )  

        def analyze_criticality(features):
            criticality_template = ChatPromptTemplate.from_messages(
                [
                    ("system", "You are an expert in finding out the criticality."),
                    (
                        "human",
                        "Given these features: {features}, return the criticality in strictly single word, either low/high. Eg. High",
                    ),
                ]
            )
            return criticality_template.format_prompt(features=features)

        def analyze_complexity(features):
            complexity_template = ChatPromptTemplate.from_messages(
                [
                    ("system", "You are an expert in finding out the complexity."),
                    (
                        "human",
                        "Given these features: {features}, return the complexity in strictly single word. either low/high. Eg. Low",
                    ),
                ]
            )
            return complexity_template.format_prompt(features=features)

        # Simplify branches with LCEL
        criticality_chain = (
            RunnableLambda(lambda x: analyze_criticality(x)) | model | StrOutputParser()
        )

        complexity_chain = (
            RunnableLambda(lambda x: analyze_complexity(x)) | model | StrOutputParser()
        )

        def combine_reponse(criticality, complexity):
            result = {
            "criticality": criticality,
            "complexity": complexity,
            }
            return result


        chain = (
            prompt_template
            | model
            | StrOutputParser()
            | RunnableParallel(branches={"criticality": criticality_chain, "complexity": complexity_chain})
            | RunnableLambda(lambda x: combine_reponse(x["branches"]["criticality"], x["branches"]["complexity"]))
        )

        result = chain.invoke({"sub_catalog_name": sub_catalog_name, "topic_summary": topic_summary})
        
        total_time = 10

        if( ("high" in result["complexity"].lower()) and ("high" in result["criticality"].lower()) ):
            total_time = 12
        elif( ("high" in result["complexity"].lower()) and ("low" in result["criticality"].lower()) ):
            total_time = 10
        elif( ("low" in result["complexity"].lower()) and ("high" in result["criticality"].lower()) ):
            total_time = 8
        elif( ("low" in result["complexity"].lower()) and ("low" in result["criticality"].lower()) ):
            total_time = 6
        else:
            total_time = 10    

        kt_weeks = ((int(kt_percent)/100)*total_time)
        kt_days = math.floor(kt_weeks*7)
        fwd_weeks = ((int(fwd_percent)/100)*total_time)
        fwd_days = math.floor(fwd_weeks*7)
        rev_weeks = ((int(rev_percent)/100)*total_time)
        rev_days = math.floor(rev_weeks*7)
        cutover_weeks = ((int(cutover_percent)/100)*total_time)
        cutover_days = math.floor(cutover_weeks*7)

        return {
            "kt_session":kt_days,
            "fwd_shadow":fwd_days,
            "rev_shadow":rev_days,
            "cutover":cutover_days
        }

    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
